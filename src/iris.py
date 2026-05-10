import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random

import requests
from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IRIS_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../")
sys.path.append(IRIS_ROOT_DIR)

from src.config import CODEQL_DIR, CODEQL_DB_PATH, PACKAGE_MODULES_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR, CODEQL_QUERY_VERSION
from src.language_config import get_language_config, normalize_language


from src.logger import Logger
from src.queries import QUERIES
from src.language_prompts import LANGUAGE_PROMPTS
from src.prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT
from src.prompts import FUNC_PARAM_LABELLING_SYSTEM_PROMPT, FUNC_PARAM_LABELLING_USER_PROMPT

from src.codeql_queries import QL_SOURCE_PREDICATE, QL_STEP_PREDICATE, QL_SINK_PREDICATE
from src.codeql_queries import EXTENSION_YML_TEMPLATE, EXTENSION_SRC_SINK_YML_ENTRY, EXTENSION_SUMMARY_YML_ENTRY
from src.codeql_queries import QL_METHOD_CALL_SOURCE_BODY_ENTRY, QL_FUNC_PARAM_SOURCE_ENTRY, QL_FUNC_PARAM_NAME_ENTRY
from src.codeql_queries import QL_SUMMARY_BODY_ENTRY, QL_BODY_OR_SEPARATOR
from src.codeql_queries import QL_SUBSET_PREDICATE, CALL_QL_SUBSET_PREDICATE
from src.codeql_queries import QL_SINK_BODY_ENTRY, QL_SINK_ARG_NAME_ENTRY, QL_SINK_ARG_THIS_ENTRY
from src.codeql_queries_python import PYTHON_QL_SOURCE_PREDICATE, PYTHON_QL_STEP_PREDICATE, PYTHON_QL_SINK_PREDICATE
from src.codeql_queries_python import PYTHON_QL_API_SOURCE_ENTRY, PYTHON_QL_FUNC_PARAM_SOURCE_ENTRY
from src.codeql_queries_python import PYTHON_QL_API_SINK_ARG_ENTRY, PYTHON_QL_STEP_ENTRY
from src.codeql_queries_cpp import CPP_QL_SOURCE_PREDICATE, CPP_QL_STEP_PREDICATE, CPP_QL_SINK_PREDICATE
from src.codeql_queries_cpp import CPP_QL_API_SOURCE_ENTRY, CPP_QL_FUNC_PARAM_SOURCE_ENTRY
from src.codeql_queries_cpp import CPP_QL_API_SINK_ARG_ENTRY, CPP_QL_STEP_ARG_TO_RETURN_ENTRY
from src.codeql_queries_cpp import CPP_QL_STEP_ARG_TO_OUTPUT_ARG_ENTRY

from src.modules.codeql_query_runner import CodeQLQueryRunner
from src.modules.contextual_analysis_pipeline import ContextualAnalysisPipeline
from src.modules.evaluation_pipeline import EvaluationPipeline
from src.modules.native_contextual_analysis_pipeline import NativeContextualAnalysisPipeline

from src.models.llm import LLM

CODEQL = f"{CODEQL_DIR}/codeql"

PRIMITIVE_TYPES = set([
    "void",
    "int",
    "boolean",
    "long",
    "Integer",
    "Boolean",
    "Object",
])

MAX_DOC_LENGTH = 50


class SAPipeline:
    def __init__(self,
            project_name: str,
            query: str,
            run_id: str = "default",
            llm: str = "gpt-4",
            label_api_batch_size: int = 30,
            label_func_param_batch_size: int = 50,
            num_threads: int = 3,
            seed: int = 1234,
            no_summary_model: bool = False,
            use_exhaustive_qll: bool = False,
            skip_huge_project: bool = False,
            skip_huge_project_num_apis_threshold: int = 3000,
            skip_posthoc_filter: bool = False,
            skip_evaluation: bool = False,
            filter_by_module: bool = False,
            filter_by_module_large: bool = False,
            posthoc_filtering_skip_fp: bool = False,
            posthoc_filtering_rerun_skipped_fp: bool = False,
            evaluation_only: bool = False,
            overwrite: bool = False,
            overwrite_api_candidates: bool = False,
            overwrite_func_param_candidates: bool = False,
            overwrite_labelled_apis: bool = False,
            overwrite_llm_cache: bool = False,
            overwrite_labelled_func_param: bool = False,
            overwrite_cwe_query_result: bool = False,
            overwrite_postprocess_cwe_query_result: bool = False,
            overwrite_posthoc_filter: bool = False,
            overwrite_debug_info: bool = False,
            debug_source: bool = False,
            debug_sink: bool = False,
            test_run: bool = False,
            no_logger: bool = False,
            use_container: bool = False,
            language: str = "java",
    ):
        # Store basic information
        self.project_name = project_name
        self.query = query
        self.language = normalize_language(language)
        self.language_config = get_language_config(self.language)
        self.llm = llm
        self.label_api_batch_size = label_api_batch_size
        self.label_func_param_batch_size = label_func_param_batch_size
        self.num_threads = num_threads
        self.seed = seed
        self.run_id = f"{run_id}-docker" if use_container else run_id
        self.no_summary_model = no_summary_model
        self.use_exhaustive_qll = use_exhaustive_qll
        self.skip_huge_project = skip_huge_project
        self.skip_huge_project_num_apis_threshold = skip_huge_project_num_apis_threshold
        self.skip_posthoc_filter = skip_posthoc_filter
        self.skip_evaluation = skip_evaluation
        self.filter_by_module = filter_by_module
        self.filter_by_module_large = filter_by_module_large
        self.posthoc_filtering_skip_fp = posthoc_filtering_skip_fp
        self.posthoc_filtering_rerun_skipped_fp = posthoc_filtering_rerun_skipped_fp
        self.evaluation_only = evaluation_only
        self.overwrite = overwrite
        self.overwrite_api_candidates = overwrite_api_candidates
        self.overwrite_func_param_candidates = overwrite_func_param_candidates
        self.overwrite_labelled_apis = overwrite_labelled_apis
        self.overwrite_llm_cache = overwrite_llm_cache
        self.overwrite_labelled_func_param = overwrite_labelled_func_param
        self.overwrite_cwe_query_result = overwrite_cwe_query_result
        self.overwrite_postprocess_cwe_query_result = overwrite_postprocess_cwe_query_result
        self.overwrite_posthoc_filter = overwrite_posthoc_filter
        self.overwrite_debug_info = overwrite_debug_info
        self.debug_source = debug_source
        self.debug_sink = debug_sink
        self.test_run = test_run
        self.no_logger = no_logger
        self.use_container = use_container

        # Setup logger
        if not self.no_logger:
            self.master_logger = Logger(f"{IRIS_ROOT_DIR}/log")

        # Check if the query is valid
        if self.query in QUERIES:
            if "cwe_id" not in QUERIES[self.query]:
                if not self.no_logger:
                    self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                    self.master_logger.error(f"==> Query `{self.query}` is not a query for detecting CWE; aborting")
                raise Exception(f"Query `{self.query}` is not a query for detecting CWE; aborting")
        else:
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Unknown query `{self.query}`; aborting")
            raise Exception(f"Unknown query `{self.query}`; aborting")
        self.cwe_id = QUERIES[self.query]["cwe_id"]

        # Load Java/CWE-Bench metadata only for the original Java route.
        self.project_source_code_dir = f"{PROJECT_SOURCE_CODE_DIR}/{self.project_name}"
        project_parts = project_name.split("_")
        self.cve_id = project_parts[3] if len(project_parts) > 3 else None
        if self.language == "java" and self.cve_id is not None and self.cve_id.startswith("CVE-"):
            self.all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)
            self.project_cve_with_commit_info = self.all_cves_with_commit[self.all_cves_with_commit["cve_id"] == self.cve_id].iloc[0]
            self.cve_fixing_commits = self.project_cve_with_commit_info["fix_commit_ids"].split(";")
        else:
            self.cve_fixing_commits = []
        if self.language == "java":
            self.fixed_methods = pd.read_csv(ALL_METHOD_INFO_DIR)
            self.project_fixed_methods = self.fixed_methods[self.fixed_methods["project_slug"] == self.project_name]
            self.project_fixed_modules = self.project_fixed_methods[
                self.project_fixed_methods["file"].str.contains("src/main") &
                self.project_fixed_methods["file"].str.endswith(".java")]
            self.fixed_modules = self.project_fixed_modules \
                .apply(lambda f: \
                    pd.Series([
                        f["file"][:f["file"].index("src/main") - 1] if f["file"].index("src/main") > 1 else ""
                    ], index=["module"]), axis=1, result_type="expand") \
                .drop_duplicates()
        else:
            self.fixed_methods = pd.DataFrame()
            self.project_fixed_methods = pd.DataFrame()
            self.project_fixed_modules = pd.DataFrame()
            self.fixed_modules = pd.DataFrame()

        # Basic path information
        self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/{self.run_id}"

        # Setup codeql database path
        db_project_name = f"{self.project_name}-docker" if self.use_container else self.project_name
        self.project_codeql_db_path = f"{CODEQL_DB_PATH}/{db_project_name}"
        if not os.path.exists(f"{self.project_codeql_db_path}/{self.language_config.database_subdir}"):
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Cannot find CodeQL database for {self.project_name}; aborting")
            raise Exception(f"Cannot find CodeQL database for {self.project_codeql_db_path}; aborting")

        # Setup consolidated analysis directory with common/ and cwe-{query}/ subdirectories
        self.analysis_output_path = f"{self.project_output_path}/analysis"
        self.analysis_common_path = f"{self.analysis_output_path}/common"
        self.analysis_cwe_path = f"{self.analysis_output_path}/{self.query}"
        os.makedirs(self.analysis_common_path, exist_ok=True)
        os.makedirs(self.analysis_cwe_path, exist_ok=True)

        # Setup custom CodeQL qlpack structure
        self.custom_codeql_root = f"{self.project_output_path}/myqueries"

        # Create qlpack.yml for the custom package
        self._create_custom_qlpack_yml()

        # Path towards external APIs (fetch query results in old structure)
        self.external_apis_csv_path = f"{self.project_output_path}/fetch_external_apis/results.csv"
        self.candidate_apis_csv_path = f"{self.analysis_common_path}/candidate_apis.csv"

        # Path towards function parameters (fetch query results in old structure)
        self.func_param_path = f"{self.project_output_path}/fetch_func_params/results.csv"
        self.source_func_param_candidates_path = f"{self.analysis_common_path}/source_func_param_candidates.csv"

        # Function and Class locations (fetch query results in old structure)
        self.func_locs_path = f"{self.project_output_path}/fetch_func_locs/results.csv"
        self.class_locs_path = f"{self.project_output_path}/fetch_class_locs/results.csv"

        # LLM labelled results (CWE-specific analysis data)
        self.llm_labelled_sink_apis_path = f"{self.analysis_cwe_path}/llm_labelled_sink_apis.json"
        self.llm_labelled_source_apis_path = f"{self.analysis_cwe_path}/llm_labelled_source_apis.json"
        self.llm_labelled_taint_prop_apis_path = f"{self.analysis_cwe_path}/llm_labelled_taint_prop_apis.json"
        self.llm_labelled_source_func_params_path = f"{self.analysis_cwe_path}/llm_labelled_source_func_params.json"

        # LLM related log paths (CWE-specific)
        self.label_api_log_path = f"{self.analysis_cwe_path}/logs/label_apis"
        self.label_func_params_log_path = f"{self.analysis_cwe_path}/logs/label_func_params"
        os.makedirs(self.label_api_log_path, exist_ok=True)
        os.makedirs(self.label_func_params_log_path, exist_ok=True)

        # CodeQL queries paths - generate files directly in final destination
        cwe_query_dir = f"{self.custom_codeql_root}/{self.query}"

        self.source_qll_path = f"{cwe_query_dir}/MySources.qll"
        self.summary_qll_path = f"{cwe_query_dir}/MySummaries.qll"
        self.sink_qll_path = f"{cwe_query_dir}/MySinks.qll"
        self.spec_yml_path = f"{cwe_query_dir}/specs.model.yml"

        # Setup query output path
        self.query_output_path = f"{self.project_output_path}/{self.query}"
        os.makedirs(self.query_output_path, exist_ok=True)
        self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        self.query_output_result_sarif_pp_path = f"{self.query_output_path}/results_pp.sarif"
        self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"

        # Setup posthoc-filtering output path
        self.posthoc_filtering_output_path = f"{self.project_output_path}/{self.query}-posthoc-filter"
        os.makedirs(self.posthoc_filtering_output_path, exist_ok=True)
        self.posthoc_filtering_output_result_sarif_path = f"{self.posthoc_filtering_output_path}/results.sarif"
        self.posthoc_filtering_output_result_json_path = f"{self.posthoc_filtering_output_path}/results.json"
        self.posthoc_filtering_output_stats_json_path = f"{self.posthoc_filtering_output_path}/stats.json"
        self.posthoc_filtering_output_log_path = f"{self.posthoc_filtering_output_path}/logs"
        os.makedirs(self.posthoc_filtering_output_log_path, exist_ok=True)

        # Setup final output path
        self.final_output_path = f"{self.project_output_path}/{self.query}-final"
        os.makedirs(self.final_output_path, exist_ok=True)
        self.final_output_json_path = f"{self.final_output_path}/results.json"

        # Create logger
        if not self.no_logger:
            self.project_logging_directory = f"{self.project_output_path}/log"
            os.makedirs(self.project_logging_directory, exist_ok=True)
            self.project_logger = Logger(self.project_logging_directory)
            self.project_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
        else:
            self.project_logger = None

        # Setup cache path
        self.common_cache_path = f"{OUTPUT_DIR}/common/{self.run_id}/cwe-{self.cwe_id}"
        if not os.path.exists(self.common_cache_path):
            os.makedirs(self.common_cache_path, exist_ok=True)
        self.api_labels_cache_path = f"{self.common_cache_path}/api_labels_{self.llm}.json"
        self.model = None

    def _create_custom_qlpack_yml(self):
        """Create qlpack.yml for the custom CodeQL package"""
        if self.language == "java":
            deps = "  codeql/java-all: \"*\"\n  codeql/java-queries: \"*\""
        elif self.language == "python":
            deps = "  codeql/python-all: \"*\"\n  codeql/python-queries: \"*\""
        else:
            deps = "  codeql/cpp-all: \"*\"\n  codeql/cpp-queries: \"*\""
        qlpack_content = f"""
name: iris
version: 1.0.0
dependencies:
{deps}
"""
        qlpack_path = f"{self.custom_codeql_root}/qlpack.yml"
        os.makedirs(self.custom_codeql_root, exist_ok=True)
        with open(qlpack_path, 'w') as f:
            f.write(qlpack_content)
            
    def get_model(self):
        if self.model is None:
            self.model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 2048})
        return self.model

    def get_language_query_config(self):
        return QUERIES[self.query].get("languages", {}).get(self.language, {})

    def get_language_prompt_config(self):
        return self.get_language_query_config().get("prompts", {})

    def get_api_labelling_prompts(self):
        language_prompts = self.get_language_prompt_config()
        api_examples = language_prompts.get("api_examples")
        if api_examples is not None:
            system_prompt = API_LABELLING_SYSTEM_PROMPT
            for old, new in LANGUAGE_PROMPTS.get(self.language, {}).get("api_system_prompt_replacements", {}).items():
                system_prompt = system_prompt.replace(old, new)
            return system_prompt, json.dumps(api_examples, indent=2)

        examples = json.dumps(QUERIES[self.query]["prompts"]["examples"], indent=2)
        return API_LABELLING_SYSTEM_PROMPT, examples

    def get_func_param_labelling_prompts(self):
        language_prompts = self.get_language_prompt_config()
        default_prompts = LANGUAGE_PROMPTS.get(self.language, {})
        return (
            language_prompts.get(
                "function_param_system_prompt",
                default_prompts.get("function_param_system_prompt", FUNC_PARAM_LABELLING_SYSTEM_PROMPT),
            ),
            language_prompts.get(
                "function_param_user_prompt",
                default_prompts.get("function_param_user_prompt", FUNC_PARAM_LABELLING_USER_PROMPT),
            ),
        )

    def get_func_param_cwe_hint(self):
        hint = self.get_language_prompt_config().get("function_param_hint", "")
        return f"{hint}\n" if hint else ""

    def run_simple_codeql_query(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        runner = CodeQLQueryRunner(self.project_output_path, self.project_codeql_db_path, self.project_logger)
        actual_query = query
        language_query = f"{query}_{self.language}"
        if self.language != "java" and language_query in QUERIES:
            actual_query = language_query
            if target_csv_path is None:
                suffix_dir = "" if suffix is None else f"/{suffix}"
                target_dir = f"{self.project_output_path}/{query}{suffix_dir}"
                os.makedirs(target_dir, exist_ok=True)
                target_csv_path = f"{target_dir}/results.csv"
        runner.run(actual_query, target_csv_path, suffix, dyn_queries)

    def keep_external_packages(self, api_candidates_df):
        if self.language != "java":
            return api_candidates_df
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]
        return api_candidates_df[~api_candidates_df["package"].isin(packages)]

    def keep_internal_packages(self, api_candidates_df):
        if self.language != "java":
            return api_candidates_df
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]
        return api_candidates_df[api_candidates_df["package"].isin(packages)]

    def api_candidate_is_in_fixed_module(self, external_api_candidate_row):
        if len(self.fixed_modules) > 0:
            return any(f"{s}/src/main" in external_api_candidate_row["location"] for s in self.fixed_modules["module"])
        else:
            return True

    def api_candidate_has_non_trivial_return(self, external_api_candidate_row):
        """
        A candidate has non trivial return if the candidate is a constructor or return non primitive type
        """
        if external_api_candidate_row["callstr"].startswith("new "): return True
        else: return external_api_candidate_row["return_type"] not in PRIMITIVE_TYPES

    def api_candidate_has_non_trivial_parameter(self, row):
        """
        A candidate has non trivial parameter if the candidate is
        1. static method with at least one non-trivial parameter
        2. non-static method
        """
        if row["is_static"]:
            param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
            param_types = param_types_raw.split(";")
            return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)
        else:
            return True

    def api_candidate_not_on_blacklist(self, external_api_candidate_row):
        row = external_api_candidate_row
        if row["package"] == "java.util" and row["clazz"] == "String": return False
        if row["package"] == "java.util" and row["clazz"] == "EnumSet": return False
        if row["package"] == "java.util" and row["clazz"] == "LinkedList": return False
        if row["package"] == "java.util" and row["clazz"] == "List": return False
        if row["package"] == "java.io" and row["clazz"] == "PrintStream": return False
        else: return True

    def api_is_candidate(self, candidate, num_external_apis):
        if self.api_candidate_not_on_blacklist(candidate):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            elif self.filter_by_module_large and num_external_apis >  self.skip_huge_project_num_apis_threshold and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            return self.api_candidate_has_non_trivial_parameter(candidate) or \
                   self.api_candidate_has_non_trivial_return(candidate)
        else:
            return False

    def collect_invoked_external_apis(self):
        self.project_logger.info("==> Stage 1: Collecting external APIs...")

        # 1. Invoke CodeQL to extract the external APIs
        if not os.path.exists(self.external_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            self.project_logger.info("  ==> Extracting all external APIs by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_external_apis")
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing external APIs file found. Skipping running CodeQL...")

        # 2. Load the API candidates
        if not os.path.exists(self.candidate_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            external_api_candidates = pd.read_csv(self.external_apis_csv_path)
            num_external_apis = len(external_api_candidates)

            # 3. Filter the APIs by internal/external, and source/sink/taint-prop
            external_api_candidates = self.keep_external_packages(external_api_candidates)
            possible_src_snk_tp = external_api_candidates.apply(lambda row: self.api_is_candidate(row, num_external_apis), axis=1)
            external_api_candidates = external_api_candidates[possible_src_snk_tp]

            # 4. Keep only the core columns (package, class, function, signature) and deduplicate
            external_api_candidates = external_api_candidates[["package", "clazz", "func", "full_signature"]].drop_duplicates()
            num_candidates = len(external_api_candidates)

            # 5. Dump the filtered API candidates
            self.project_logger.info(f"  ==> #Relevant API Calls: {num_external_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered API candidates...")
            external_api_candidates.to_csv(self.candidate_apis_csv_path, index=False, header=True, sep=',', encoding='utf-8')
        else:
            self.project_logger.info("  ==> Existing candidate APIs file found. Skipping filtering candidates...")

    def func_parameter_has_non_trivial_parameter(self, row):
        param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
        param_types = param_types_raw.split(";")
        return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)

    def func_parameter_not_on_blacklist(self, row):
        if row["func"] == "isEqual" or row["func"] == "toString" or row["func"] == "equals" or row["func"] == "canConvert" or row["func"] == "compareTo" or row["func"] == "compare":
            return False
        elif "src/test" in row["location"]:
            return False
        else:
            return True

    def func_parameter_is_candidate(self, row):
        if self.func_parameter_not_on_blacklist(row):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(row):
                return False
            return self.func_parameter_has_non_trivial_parameter(row)
        else:
            return False

    def collect_internal_function_parameters(self):
        self.project_logger.info("==> Stage 2: Collecting internal function parameters...")

        # 1. Invoke CodeQL to extract the internal function parameters
        if not os.path.exists(self.func_param_path) or self.overwrite or self.overwrite_func_param_candidates:
            self.project_logger.info("  ==> Extracting all function parameters by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_func_params")
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing function parameter file found. Skipping running CodeQL...")

        # 2. Filter it to get function parameter source candidates
        if not os.path.exists(self.source_func_param_candidates_path) or self.overwrite or self.overwrite_func_param_candidates:
            func_param_candidates = pd.read_csv(self.func_param_path, keep_default_na=False)
            num_internal_apis = len(func_param_candidates)

            # 3. Filter the APIs by internal
            func_param_candidates = self.keep_internal_packages(func_param_candidates)
            possible_func_param = func_param_candidates.apply(lambda row: self.func_parameter_is_candidate(row), axis=1)
            func_param_candidates = func_param_candidates[possible_func_param]

            # 4. Keep only the relevant fields for candidates
            func_param_candidates = func_param_candidates[["package", "clazz", "func", "full_signature", "doc"]]
            num_candidates = len(func_param_candidates)

            # 5. Dump the func param candidates
            self.project_logger.info(f"  ==> #Relevant APIs: {num_internal_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered function parameter candidates...")
            func_param_candidates.to_csv(self.source_func_param_candidates_path, index=False, header=True, sep=",", encoding="utf-8")
        else:
            self.project_logger.info("  ==> Existing source function parameter candidates file found. Skipping filtering candidates...")

    def load_cached_llm_labeled_apis(self):
        if os.path.exists(self.api_labels_cache_path):
            return json.load(open(self.api_labels_cache_path))
        else:
            return []

    def filter_to_query_apis_with_cache(self, candidates):
        """
        :param candidates, a list of the following [(<package>, <class>, <method>, <signature>), ...]
        """
        llm_results = self.load_cached_llm_labeled_apis()
        cached_apis = set([(item["package"], item["class"], item["method"], item["signature"]) for item in llm_results])
        remaining_apis = sorted(list(set(candidates).difference(cached_apis)))
        return remaining_apis

    def merge_llm_labeled_apis_and_cache(self, candidates, new_llm_result):
        cached_result = self.load_cached_llm_labeled_apis()
        cached_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in cached_result}
        new_llm_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in new_llm_result}

        result = []
        for item in candidates:
            item_key = ",".join(item)
            if item_key in new_llm_mapping:
                result.append(new_llm_mapping[item_key])
            elif item_key in cached_mapping:
                if cached_mapping[item_key].get("type", "") != "none":
                    copy_of_cached_item = {k: v for (k, v) in cached_mapping[item_key].items()}
                    result.append(copy_of_cached_item)
        return result

    def cache_llm_results(self, candidates, new_llm_result):
        if os.path.exists(self.api_labels_cache_path):
            try:
                cache = json.load(open(self.api_labels_cache_path))
            except json.JSONDecodeError as e:
                self.project_logger.error(f"Error when loading cache: {self.api_labels_cache_path}\n{e}"); exit(1)
        else:
            cache = []
        cached_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in cache}
        llm_returned_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in new_llm_result}
        for item in candidates:
            if item in cached_apis:
                if item in llm_returned_apis:
                    cached_apis[item]["type"] = llm_returned_apis[item].get("type", "none")
                else:
                    cached_apis[item]["type"] = "none"
            else:
                if item in llm_returned_apis:
                    to_cache_obj = {k: v for (k, v) in llm_returned_apis[item].items()}
                else:
                    to_cache_obj = {"package": item[0], "class": item[1], "method": item[2], "signature": item[3], "type": "none"}
                cached_apis[item] = to_cache_obj
        reload_cache = [cached_apis[item] for item in sorted(cached_apis.keys())]
        json.dump(reload_cache, open(self.api_labels_cache_path, "w"), indent=2)

    def parse_json(self, json_str):
        def normalize_json_result(result):
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                for key in ("results", "items", "labels", "apis", "functions"):
                    value = result.get(key)
                    if isinstance(value, list):
                        return value
                return [result]
            return []

        def strip_code_fences(text):
            text = text.strip()
            fenced = re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", text)
            if fenced:
                return fenced.group(1).strip()
            return text

        def first_balanced_json_array(text):
            start = text.find("[")
            while start != -1:
                depth = 0
                in_string = False
                escape = False
                for idx in range(start, len(text)):
                    ch = text[idx]
                    if in_string:
                        if escape:
                            escape = False
                        elif ch == "\\":
                            escape = True
                        elif ch == "\"":
                            in_string = False
                        continue
                    if ch == "\"":
                        in_string = True
                    elif ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            return text[start:idx + 1]
                start = text.find("[", start + 1)
            return None

        try:
            json_str = strip_code_fences(str(json_str))
            json_str = json_str.replace("\\'", "'")
            json_str = json_str.replace("\\n", "").replace("\\\n", "")
            json_str = re.sub(r"//.*", "", json_str)
            json_str = re.sub(r"\"\"", "\"", json_str)

            try:
                return normalize_json_result(json.loads(json_str))
            except Exception:
                pass

            json_array = first_balanced_json_array(json_str)
            if not json_array:
                self.project_logger.error("Error parsing JSON: No JSON array found in response")
                self.project_logger.error(f"Problematic JSON string: {repr(json_str[:500])}")
                return []
            return normalize_json_result(json.loads(json_array))
        except Exception as e:
            print(e)
            try:
                self.project_logger.error("Error parsing JSON 1. Trying list parsing")
                results = re.findall(r"{[^}]*}", json_str)
                return [json.loads(r.strip()) for r in results]
            except Exception as e:
                print(e)
                self.project_logger.error("Error parsing JSON 2")
                self.project_logger.error(f"Problematic JSON string: {repr(str(json_str)[:500])}")
        return []

    def query_gpt_for_api_src_tp_sink_batched(self):
        self.project_logger.info("==> Stage 3: Querying GPT for source/taint-prop/sink APIs...")

        # Check if there is labelled sink/source/taint-propagator
        if not os.path.exists(self.llm_labelled_source_apis_path) or self.overwrite or self.overwrite_labelled_apis:
            # 1. Load the candidates
            candidates_csv = pd.read_csv(self.candidate_apis_csv_path, keep_default_na=False)
            candidates = [(row["package"], row["clazz"], row["func"], row["full_signature"]) for (_, row) in candidates_csv.iterrows()]

            # 6. If the candidates are too many, exit
            if self.skip_huge_project and len(candidates) > self.skip_huge_project_num_apis_threshold:
                self.project_logger.info("  ==> Skipping project due to it being too large...")
                exit(0)

            # 2. Load the cache (if needed), and eliminate candidates for querying
            if self.overwrite_llm_cache:
                to_query_candidates = candidates
            else:
                to_query_candidates = self.filter_to_query_apis_with_cache(candidates)
            num_cached_candidates = len(candidates) - len(to_query_candidates)
            self.project_logger.info(f"  ==> Querying GPT... #Candidates: {len(candidates)}, #To Query APIs: {len(to_query_candidates)}, #Cached: {num_cached_candidates}")

            # 3. Setup LLMs and relevant queries
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})
            system_prompt, cwe_examples = self.get_api_labelling_prompts()
            cwe_description = QUERIES[self.query]["prompts"]["desc"]
            cwe_long_description = QUERIES[self.query]["prompts"]["long_desc"]

            # 4. Setup dispatch function. This function will be invoked for each batch, where i = 0, batch_size, 2 * batch_size, ...
            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = to_query_candidates[i:i + self.label_api_batch_size]
                api_list_text = "\n".join([",".join(row) for row in batch])

                # 4.2. Build the user prompt and dump it
                user_prompt = API_LABELLING_USER_PROMPT.format(
                    cwe_description=cwe_description,
                    cwe_id=self.cwe_id,
                    cwe_long_description=cwe_long_description,
                    cwe_examples=cwe_examples,
                    methods=api_list_text)
                with open(f"{self.label_api_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")

                return [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

                # 4.4. Parse the GPT result
                #json_result = self.parse_json(result)
                #return json_result

            # 5. Iterate through all batches and generate result
            args = range(0, len(to_query_candidates), self.label_api_batch_size)
            indiv_prompts = [process_candidate_batch(i) for i in args]
            indiv_results = []
            responses = self.get_model().predict(indiv_prompts, batch_size=self.num_threads)
            for i, response in zip(args, responses):
                json_result = self.parse_json(response)
                with open(f"{self.label_api_log_path}/raw_llm_response_{i}.txt", "w") as f:
                    f.write(str(response) + "\n")
                indiv_results.append(json_result)

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)
            merged_llm_results=self.filter_invalid_entries(merged_llm_results)
            # 7. Save the result for this project
            merged_overall_results = self.merge_llm_labeled_apis_and_cache(candidates, merged_llm_results)
            sources = [r for r in merged_overall_results if r.get("type", "") == "source"]
            taint_props = [r for r in merged_overall_results if r.get("type", "") == "taint-propagator"]
            sinks = [r for r in merged_overall_results if r.get("type", "") == "sink"]
            self.project_logger.info(f"  ==> #APIs Labelled by LLM: {len(merged_overall_results)}, #Source: {len(sources)}, #Sink: {len(sinks)}, #Taint Propagators: {len(taint_props)}")
            if not self.test_run:
                json.dump(sources, open(self.llm_labelled_source_apis_path, "w"), indent=2)
                json.dump(taint_props, open(self.llm_labelled_taint_prop_apis_path, "w"), indent=2)
                json.dump(sinks, open(self.llm_labelled_sink_apis_path, "w"), indent=2)

            # 8. Save the results for common cache
            if not self.test_run:
                self.cache_llm_results(candidates, merged_overall_results)
        else:
            self.project_logger.info("  ==> Existing labelled source/taint-prop/sink APIs found. Skipping querying GPT...")

    def first_project_description_paragraph(self, readme_lines):
        filtered_lines = []
        prev_line_is_empty = True
        for line in readme_lines:
            if len(filtered_lines) > 10:
                break
            if line.strip() == "":
                if prev_line_is_empty:
                    continue
                else:
                    filtered_lines.append("")
                    prev_line_is_empty = True
            elif line.strip()[0].isalpha():
                filtered_lines.append(line.strip())
            else:
                if prev_line_is_empty:
                    continue
                else:
                    filtered_lines.append("")
                    prev_line_is_empty = True
        return "\n".join(filtered_lines)

    def fetch_project_description_from_commit_readme(self, commit_link):
        # Try for each possible readme file
        for possible_readme_file_name in ["README.md", "README.adoc", "README", "readme.md", "readme"]:
            link = commit_link + "/" + possible_readme_file_name
            self.project_logger.info(f"  ==> Attempting to fetch project readme from {link}...")
            try:
                response = requests.get(link)
                if response.status_code == 200:
                    self.project_logger.info(f"  ==> Success!")
                    lines = response.text.split('\n')
                    first_markdown_paragraph = self.first_project_description_paragraph(lines)

                    # Success. Dump the readme and the head
                    with open(f"{self.label_func_params_log_path}/readme.txt", "w") as f:
                        f.write("\n".join(lines))
                    with open(f"{self.label_func_params_log_path}/readme_head.txt", "w") as f:
                        f.write(first_markdown_paragraph)

                    return first_markdown_paragraph
                else:
                    self.project_logger.info(f"  ==> Fail")
            except Exception as e:
                self.project_logger.info(f"  ==> Fail with error: {e}")

    def fetch_project_description_from_readme(self):
        readme_head_txt_path = f"{self.label_func_params_log_path}/readme_head.txt"
        if os.path.exists(readme_head_txt_path) and not self.overwrite:
            self.project_logger.info("  ==> Found fetched readme. Skipping fetch project description...")
            return "".join(list(open(readme_head_txt_path)))
        if self.language != "java":
            for possible_readme_file_name in ["README.md", "README", "readme.md", "readme"]:
                readme_path = f"{self.project_source_code_dir}/{possible_readme_file_name}"
                if os.path.exists(readme_path):
                    lines = open(readme_path, encoding="utf-8", errors="ignore").read().splitlines()
                    paragraph = self.first_project_description_paragraph(lines)
                    with open(readme_head_txt_path, "w") as f:
                        f.write(paragraph)
                    return paragraph
            return f"Python project {self.project_name}."
        else:
            # There has to be some commit associated with this CVE
            if len(self.cve_fixing_commits) == 0:
                self.project_logger.error("  ==> No fixing commits found for project; aborting"); return

            # Get repository information from the CSV data
            github_username = self.project_cve_with_commit_info["github_username"]
            github_repo = self.project_cve_with_commit_info["github_repository_name"]
            repo_base = f"https://raw.githubusercontent.com/{github_username}/{github_repo}"

            # Iterate through all commit hashes
            for commit_hash in self.cve_fixing_commits:
                base_link = f"{repo_base}/{commit_hash}"
                paragraph = self.fetch_project_description_from_commit_readme(base_link)
                if paragraph is not None:
                    return paragraph

            # If not successful, fallback to master branch
            base_link = f"{repo_base}/master"
            paragraph = self.fetch_project_description_from_commit_readme(base_link)
            if paragraph is not None:
                return paragraph

            # At this stage, it is failed
            self.project_logger.error(f"  ==> Cannot pull project readme. Aborting..."); return

    def get_project_owner_and_name(self):
        if self.language == "java" and len(self.project_name.split("_")) > 2:
            return self.project_name.split("_")[0], self.project_name.split("_")[2]
        return "local", self.project_name

    def extract_doc(self, doc_str):
        if doc_str is None:
            return ""
        elif len(doc_str) <= MAX_DOC_LENGTH:
            return doc_str
        else:
            return doc_str[:MAX_DOC_LENGTH] + "..."

    def fetch_func_param_src_candidates(self):
        candidates_csv = pd.read_csv(self.source_func_param_candidates_path, keep_default_na=False)

        # Do deduplication
        dedup_map = {}
        for (_, row) in candidates_csv.iterrows():
            key = (row["package"], row["clazz"], row["func"])
            if key not in dedup_map:
                dedup_map[key] = row
            else:
                if row["doc"] != "":
                    dedup_map[key] = row
                elif len(row["full_signature"]) > len(dedup_map[key]["full_signature"]):
                    dedup_map[key] = row

        # Add doc into the candidates
        candidates = [(key[0], key[1], key[2], row["full_signature"], self.extract_doc(row["doc"])) for (key, row) in dedup_map.items()]

        # Count the number of functions with documentations
        num_with_docs = len([() for cand in candidates if cand[4] != ""])
        self.project_logger.info(f"  ==> #Candidate functions with source param: {len(candidates_csv)}; after deduplication: {len(candidates)}; with documentations: {num_with_docs}. Querying LLM...")

        # Return
        return candidates

    def normalize_python_source_func_param_results(self, results, candidates):
        candidate_by_func = {func: (package, clazz, func, signature, doc) for package, clazz, func, signature, doc in candidates}
        candidate_by_signature = {signature: (package, clazz, func, signature, doc) for package, clazz, func, signature, doc in candidates}
        normalized_results = []
        for result in results:
            if not isinstance(result, dict):
                continue
            method = str(result.get("method", "")).strip()
            signature = str(result.get("signature", "")).strip()
            method_without_args = re.sub(r"\(.*\)$", "", method).strip()
            candidate = (
                candidate_by_func.get(method)
                or candidate_by_func.get(method_without_args)
                or candidate_by_signature.get(signature)
            )
            if candidate is None:
                for candidate_signature, candidate_row in candidate_by_signature.items():
                    if method and candidate_signature.startswith(method_without_args + "("):
                        candidate = candidate_row
                        break
            if candidate is None:
                continue

            package, clazz, func, full_signature, _ = candidate
            tainted_input = result.get("tainted_input", [])
            if isinstance(tainted_input, str):
                tainted_input = [tainted_input]
            tainted_input = [str(arg).strip() for arg in tainted_input if str(arg).strip()]
            if not tainted_input:
                continue

            normalized_results.append({
                "package": package,
                "class": clazz,
                "method": func,
                "signature": full_signature,
                "tainted_input": tainted_input,
            })
        return normalized_results

    def query_gpt_for_func_param_src(self):
        self.project_logger.info("==> Stage 4: Querying GPT for source function parameters...")
        if self.language not in {"java", "python", "cpp"}:
            self.project_logger.info(f"  ==> {self.language} first version skips internal function parameter labelling...")
            if not os.path.exists(self.llm_labelled_source_func_params_path) or self.overwrite or self.overwrite_labelled_func_param:
                json.dump([], open(self.llm_labelled_source_func_params_path, "w"), indent=2)
            return

        if not os.path.exists(self.llm_labelled_source_func_params_path) or self.overwrite or self.overwrite_labelled_func_param:
            # 1. Get LLM and fetch information used for prompt
            system_prompt, user_prompt_template = self.get_func_param_labelling_prompts()
            proj_description = self.fetch_project_description_from_readme()
            proj_username, proj_name = self.get_project_owner_and_name()

            # 2. Get LLM
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})

            # 3. Load the candidates
            candidates = self.fetch_func_param_src_candidates()

            # 4. Setup dispatch function. This function will be invoked for each batch, where i = 0, batch_size, 2 * batch_size, ...
            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = candidates[i:i + self.label_func_param_batch_size]
                if self.language in {"python", "cpp"}:
                    api_list_text = "\n".join([",".join([row[0], row[1], row[2], row[3], row[4]]) for row in batch])
                else:
                    api_list_text = "\n".join([",".join([row[0], row[1], row[3], row[4]]) for row in batch])

                # 4.2. Build the user prompt and dump it
                user_prompt = user_prompt_template.format(
                    project_username=proj_username,
                    project_name=proj_name,
                    project_readme_summary=proj_description,
                    cwe_hint=self.get_func_param_cwe_hint(),
                    methods=api_list_text)
                with open(f"{self.label_func_params_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")


                return [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]

            # 5. Actually dispatch the tasks
            # args = range(0, len(candidates), self.label_func_param_batch_size)
            # indiv_results = thread_map(process_candidate_batch, args, max_workers=self.num_threads)

            args = range(0, len(candidates), self.label_func_param_batch_size)
            indiv_prompts = [process_candidate_batch(i) for i in args]
            indiv_results = []
            responses = self.get_model().predict(indiv_prompts, batch_size=self.num_threads)
            for i, response in zip(args, responses):
                json_result = self.parse_json(response)
                with open(f"{self.label_func_params_log_path}/raw_llm_response_{i}.txt", "w") as f:
                        f.write(response + "\n")
                indiv_results.append(json_result)

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)
            if self.language in {"python", "cpp"}:
                merged_llm_results = self.normalize_python_source_func_param_results(merged_llm_results, candidates)

            # 7. Save the result for this project
            self.project_logger.info(f"  ==> Finished querying LLM. #Function with source param: {len(merged_llm_results)}")
            if not self.test_run:
                json.dump(merged_llm_results, open(self.llm_labelled_source_func_params_path, "w"), indent=2)
        else:
            self.project_logger.info(f"  ==> Found labelled source function parameters. Skipping...")

    def not_none(self, d, keys):
        return isinstance(d, dict) and all([d.get(k, None) for k in keys])

    def filter_invalid_entries(self, api_list):
        return [api for api in api_list if self.not_none(api, ["method", "class", "package", "signature"])]

    def python_api_expr(self, api):
        method = str(api.get("method", "")).strip()
        package = str(api.get("package", "")).strip()
        method = re.sub(r"\(.*\)$", "", method)
        if method.startswith("Function "):
            method = method[len("Function "):]
        if method.endswith("()"):
            method = method[:-2]

        if "." in method:
            parts = [p for p in method.split(".") if p]
        elif package and package not in {"python", "builtins", "module"}:
            parts = [package, method]
        elif package == "builtins":
            parts = [method]
        else:
            parts = [method]

        if len(parts) == 1:
            return f'API::builtin("{parts[0]}")'

        expr = f'API::moduleImport("{parts[0]}")'
        for part in parts[1:]:
            expr += f'.getMember("{part}")'
        return expr

    def python_call_name(self, api):
        method = str(api.get("method", "")).strip()
        method = re.sub(r"\(.*\)$", "", method)
        if method.startswith("Function "):
            method = method[len("Function "):]
        if method.endswith("()"):
            method = method[:-2]
        return method

    def ql_string_escape(self, value):
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    def python_param_name_and_index(self, arg_name):
        raw_arg = str(arg_name).strip()
        match = re.fullmatch(r"p?([0-9]+)", raw_arg)
        if match:
            return raw_arg, int(match.group(1))
        return raw_arg, -1

    def python_api_arg_count(self, api):
        signature = str(api.get("signature", ""))
        match = re.search(r"\((.*)\)", signature)
        if not match:
            return 1
        args = [arg.strip() for arg in match.group(1).split(";") if arg.strip()]
        if not args:
            comma_args = [arg.strip() for arg in match.group(1).split(",") if arg.strip()]
            args = comma_args
        return max(len(args), 1)

    def build_python_source_qll_with_enumeration(self):
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_api_entries = [
            PYTHON_QL_API_SOURCE_ENTRY.format(api_expr=self.python_api_expr(api))
            for api in source_apis
        ]

        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        source_param_entries = []
        for param_func in source_params:
            for arg_name in param_func.get("tainted_input", []):
                if arg_name == "this":
                    continue
                param_name, param_index = self.python_param_name_and_index(arg_name)
                source_param_entries.append(
                    PYTHON_QL_FUNC_PARAM_SOURCE_ENTRY.format(
                        function=self.ql_string_escape(param_func["method"]),
                        param=self.ql_string_escape(param_name),
                        param_index=param_index,
                    )
                )

        all_entries = source_api_entries + source_param_entries
        body = QL_BODY_OR_SEPARATOR.join(all_entries) if all_entries else "    1 = 0"
        return PYTHON_QL_SOURCE_PREDICATE.format(body=body, additional="")

    def build_python_sink_qll_with_enumeration(self):
        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        sink_entries = []
        for api in sink_apis:
            sink_args = api.get("sink_args", ["p0"]) or ["p0"]
            for sink_arg in sink_args:
                match = re.findall(r"p?([0-9]+)", str(sink_arg))
                if match:
                    sink_entries.append(
                        PYTHON_QL_API_SINK_ARG_ENTRY.format(
                            api_expr=self.python_api_expr(api),
                            arg_id=int(match[0]),
                            call_name=self.ql_string_escape(self.python_call_name(api)),
                        )
                    )
        body = QL_BODY_OR_SEPARATOR.join(sink_entries) if sink_entries else "    1 = 0"
        return PYTHON_QL_SINK_PREDICATE.format(body=body, additional="")

    def build_python_taint_propagator_qll_with_enumeration(self):
        summary_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))
        if len(summary_apis) == 0 or self.no_summary_model:
            body = "    prev = next and 1 = 0"
        else:
            entries = []
            for api in summary_apis:
                for arg_id in range(self.python_api_arg_count(api)):
                    entries.append(
                        PYTHON_QL_STEP_ENTRY.format(
                            api_expr=self.python_api_expr(api),
                            arg_id=arg_id,
                            call_name=self.ql_string_escape(self.python_call_name(api)),
                        )
                    )
            body = QL_BODY_OR_SEPARATOR.join(entries)
        return PYTHON_QL_STEP_PREDICATE.format(body=body)

    def cpp_function_name(self, api):
        method = str(api.get("method", "")).strip()
        method = re.sub(r"\(.*\)$", "", method)
        if "::" in method:
            method = method.split("::")[-1]
        if "." in method:
            method = method.split(".")[-1]
        return method

    def cpp_param_name_and_index(self, raw_arg):
        raw_arg = str(raw_arg).strip()
        match = re.fullmatch(r"p?([0-9]+)", raw_arg)
        if match:
            return raw_arg, int(match.group(1))
        return raw_arg, -1

    def cpp_api_arg_count(self, api):
        signature = str(api.get("signature", ""))
        match = re.search(r"\((.*)\)", signature)
        if not match:
            return 1
        args = [arg.strip() for arg in match.group(1).split(";") if arg.strip()]
        if not args:
            args = [arg.strip() for arg in match.group(1).split(",") if arg.strip()]
        # C varargs declarations such as sprintf often expose only fixed
        # parameters in CodeQL metadata; generate a few extra slots so LLM
        # summaries can cover the user-controlled formatted values.
        if self.cpp_output_buffer_arg_index(api) >= 0:
            return max(len(args), 8)
        return max(len(args), 1)

    def cpp_output_buffer_arg_index(self, api):
        method = self.cpp_function_name(api)
        output_first = {
            "sprintf", "snprintf", "vsprintf", "vsnprintf",
            "strcpy", "strncpy", "strcat", "strncat",
            "memcpy", "memmove",
        }
        if method in output_first:
            return 0
        return -1

    def build_cpp_source_qll_with_enumeration(self):
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_api_entries = [
            CPP_QL_API_SOURCE_ENTRY.format(
                function=self.ql_string_escape(self.cpp_function_name(api)),
            )
            for api in source_apis
        ]

        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        source_param_entries = []
        for param_func in source_params:
            for arg_name in param_func.get("tainted_input", []):
                param_name, param_index = self.cpp_param_name_and_index(arg_name)
                source_param_entries.append(
                    CPP_QL_FUNC_PARAM_SOURCE_ENTRY.format(
                        function=self.ql_string_escape(self.cpp_function_name(param_func)),
                        param=self.ql_string_escape(param_name),
                        param_index=param_index,
                    )
                )

        all_entries = source_api_entries + source_param_entries
        body = QL_BODY_OR_SEPARATOR.join(all_entries) if all_entries else "    1 = 0"
        return CPP_QL_SOURCE_PREDICATE.format(body=body, additional="")

    def build_cpp_sink_qll_with_enumeration(self):
        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        sink_entries = []
        for api in sink_apis:
            sink_args = api.get("sink_args", ["p0"]) or ["p0"]
            for sink_arg in sink_args:
                _, arg_index = self.cpp_param_name_and_index(sink_arg)
                if arg_index >= 0:
                    sink_entries.append(
                        CPP_QL_API_SINK_ARG_ENTRY.format(
                            function=self.ql_string_escape(self.cpp_function_name(api)),
                            arg_id=arg_index,
                        )
                    )
        body = QL_BODY_OR_SEPARATOR.join(sink_entries) if sink_entries else "    1 = 0"
        return CPP_QL_SINK_PREDICATE.format(body=body, additional="")

    def build_cpp_taint_propagator_qll_with_enumeration(self):
        summary_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))
        entries = []
        if len(summary_apis) == 0 or self.no_summary_model:
            body = "    prev = next and 1 = 0"
        else:
            for api in summary_apis:
                output_arg = self.cpp_output_buffer_arg_index(api)
                arg_count = self.cpp_api_arg_count(api)
                for arg_id in range(arg_count):
                    if arg_id == output_arg:
                        continue
                    if output_arg >= 0:
                        entries.append(
                            CPP_QL_STEP_ARG_TO_OUTPUT_ARG_ENTRY.format(
                                function=self.ql_string_escape(self.cpp_function_name(api)),
                                src_arg_id=arg_id,
                                dst_arg_id=output_arg,
                            )
                        )
                    else:
                        entries.append(
                            CPP_QL_STEP_ARG_TO_RETURN_ENTRY.format(
                                function=self.ql_string_escape(self.cpp_function_name(api)),
                                arg_id=arg_id,
                            )
                        )
            body = QL_BODY_OR_SEPARATOR.join(entries) if entries else "    prev = next and 1 = 0"
        return CPP_QL_STEP_PREDICATE.format(body=body)

    def build_source_qll_with_enumeration(self):
        if self.language == "python":
            return self.build_python_source_qll_with_enumeration()
        if self.language == "cpp":
            return self.build_cpp_source_qll_with_enumeration()

        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_api_entries = [
            QL_METHOD_CALL_SOURCE_BODY_ENTRY.format(
                method=api["method"],
                package=api["package"],
                clazz=api["class"],
            ) for api in source_apis
        ]
        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        source_params_entries = [
            QL_FUNC_PARAM_SOURCE_ENTRY.format(
                method=param_func["method"],
                package=param_func["package"],
                clazz=param_func["class"],
                params=" or ".join([
                    QL_FUNC_PARAM_NAME_ENTRY.format(
                        arg_name=arg_name
                    ) for arg_name in param_func["tainted_input"]
                ]),
            )
            if isinstance(param_func, dict) and len(param_func.get("tainted_input", [])) > 0
            else "1 = 0"
            for param_func in source_params
        ]
        all_entries = source_api_entries + source_params_entries
        if len(all_entries) == 0:
            all_entries = ["1 = 0"]

        batch_size = 300
        if len(all_entries) > batch_size:
            num_batches = int(math.ceil(len(all_entries) / batch_size))
            body = " or\n".join([
                CALL_QL_SUBSET_PREDICATE.format(part_id=i, kind="Source", node="src")
                for i in range(num_batches)])
            additional = "\n\n".join([
                QL_SUBSET_PREDICATE.format(
                    part_id=i,
                    kind="Source",
                    node="src",
                    body=QL_BODY_OR_SEPARATOR.join(all_entries[i * batch_size : (i + 1) * batch_size]))
                for i in range(num_batches)
            ])
        else:
            body = QL_BODY_OR_SEPARATOR.join(all_entries)
            additional = ""

        my_source_content = QL_SOURCE_PREDICATE.format(body=body, additional=additional)
        return my_source_content

    def build_and_save_source_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.source_qll_path), exist_ok=True)
        with open(self.source_qll_path, "w") as f:
            f.write(self.build_source_qll_with_enumeration())

    def build_and_save_source_qll_with_source_node(self):
        my_source_content = QL_SOURCE_PREDICATE.format(
            body=f"sourceNode(src, \"{self.project_name}\")")
        os.makedirs(os.path.dirname(self.source_qll_path), exist_ok=True)
        with open(self.source_qll_path, "w") as f:
            f.write(my_source_content)

    def build_taint_propagator_qll_with_enumeration(self):
        if self.language == "python":
            return self.build_python_taint_propagator_qll_with_enumeration()
        if self.language == "cpp":
            return self.build_cpp_taint_propagator_qll_with_enumeration()

        summary_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        if len(summary_apis) == 0 or self.no_summary_model:
            body = "1 = 0"
        else:
            body = QL_BODY_OR_SEPARATOR.join([
                QL_SUMMARY_BODY_ENTRY.format(
                    package=api["package"],
                    clazz=api["class"],
                    method=api["method"],
                ) for api in summary_apis
            ])
        my_summary_content = QL_STEP_PREDICATE.format(body=body)
        return my_summary_content

    def build_and_save_taint_propagator_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.summary_qll_path), exist_ok=True)
        with open(self.summary_qll_path, "w") as f:
            f.write(self.build_taint_propagator_qll_with_enumeration())

    def build_sink_qll_with_enumeration(self):
        if self.language == "python":
            return self.build_python_sink_qll_with_enumeration()
        if self.language == "cpp":
            return self.build_cpp_sink_qll_with_enumeration()

        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        if len(sink_apis) == 0:
            body = "1 = 0"
            additional = ""
        else:
            def sink_body_entry(api):
                if "sink_args" in api and \
                    any(
                        len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        for sink_arg in api["sink_args"]
                    ):
                    return QL_SINK_BODY_ENTRY.format(
                        method=api["method"],
                        package=api["package"],
                        clazz=api["class"],
                        args=" or ".join([
                            QL_SINK_ARG_THIS_ENTRY if sink_arg == "this" else
                            QL_SINK_ARG_NAME_ENTRY.format(
                                arg_id=int(re.findall(r"[\S\s]*p([0-9]+)", sink_arg)[0]), # sink_arg will be `pX` where X is a number
                            )
                            for sink_arg in api["sink_args"]
                            if len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        ])
                    )
                else:
                    return "1 = 0"

            def sink_body(apis):
                return QL_BODY_OR_SEPARATOR.join([sink_body_entry(api) for api in sink_apis])

            batch_size = 300
            if len(sink_apis) > batch_size:
                num_batches = int(math.ceil(len(sink_apis) / batch_size))
                body = " or\n".join([
                    CALL_QL_SUBSET_PREDICATE.format(part_id=i, kind="Sink", node="snk")
                    for i in range(num_batches)])
                additional = "\n\n".join([
                    QL_SUBSET_PREDICATE.format(
                        part_id=i,
                        kind="Sink",
                        node="snk",
                        body=sink_body(sink_apis[i * batch_size : (i + 1) * batch_size]))
                    for i in range(num_batches)
                ])
            else:
                body = sink_body(sink_apis)
                additional = ""
        my_sink_content = QL_SINK_PREDICATE.format(body=body, additional=additional)
        return my_sink_content

    def build_and_save_sink_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.sink_qll_path), exist_ok=True)
        with open(self.sink_qll_path, "w") as f:
            f.write(self.build_sink_qll_with_enumeration())

    def build_and_save_sink_qll_with_sink_node(self):
        my_sink_content = QL_SINK_PREDICATE.format(
            body=f"sinkNode(snk, \"{self.project_name}\")")
        os.makedirs(os.path.dirname(self.sink_qll_path), exist_ok=True)
        with open(self.sink_qll_path, "w") as f:
            f.write(my_sink_content)

    def build_extension_yml(self):
        if self.language != "java":
            return "extensions: []\n"

        # First load labelled sources, sinks, and taint-propagators
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        taint_prop_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        # Convert into entries
        source_api_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_api["package"],
                clazz=source_api["class"],
                method=source_api["method"],
                access="ReturnValue",
                tag=self.project_name,
            ) for source_api in source_apis if isinstance(source_api, dict)
        ])
        source_params=[k for k in source_params if isinstance(k, dict)]
        source_func_parm_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_func_param["package"],
                clazz=source_func_param["class"],
                method=source_func_param["method"],
                access=f"Parameter[{'this' if param_name == 'this' else param_name[1:]}]",
                tag=self.project_name,
            )
            for source_func_param in source_params
            for param_name in source_func_param.get("tainted_input", [])
        ])
        sink_api_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=sink_api["package"],
                clazz=sink_api["class"],
                method=sink_api["method"],
                access="Argument[0..10]",
                tag=self.project_name,
            )
            for sink_api in sink_apis if isinstance(sink_api, dict)
            # for arg_name in sink_api["sink_args"]
        ])

        # Build the final yaml
        yml_content = EXTENSION_YML_TEMPLATE.format(
            sources="\n".join([source_api_entries, source_func_parm_entries]),
            sinks=sink_api_entries)

        return yml_content

    def get_registered_query_files(self):
        query_config = QUERIES[self.query]
        language_config = query_config.get("languages", {}).get(self.language)
        if language_config is not None:
            return language_config["queries"]
        return query_config["queries"]

    def build_and_save_extension_yml(self):
        os.makedirs(os.path.dirname(self.spec_yml_path), exist_ok=True)
        with open(self.spec_yml_path, "w") as f:
            f.write(self.build_extension_yml())

    def build_project_specific_query(self):
        if self.test_run: return

        self.project_logger.info("==> Stage 5: Building project specific query...")

        self.project_logger.info("  ==> Building source query...")
        if self.use_exhaustive_qll:
            self.build_and_save_source_qll_with_enumeration()
        else:
            self.build_and_save_source_qll_with_source_node()

        self.project_logger.info("  ==> Building taint-propagator query...")
        self.build_and_save_taint_propagator_qll_with_enumeration()

        self.project_logger.info("  ==> Building sink query...")
        if self.use_exhaustive_qll:
            self.build_and_save_sink_qll_with_enumeration()
        else:
            self.build_and_save_sink_qll_with_sink_node()

        # NOT WORKING YAML
        self.project_logger.info("  ==> Building extension yml...")
        self.build_and_save_extension_yml()

    def find_vulnerability(self):
        self.project_logger.info("==> Stage 6: Finding vulnerabilities with CodeQL...")

        # Step 0: Check if result already exists
        if os.path.exists(self.query_output_result_sarif_path) and not self.overwrite and not self.overwrite_cwe_query_result:
            self.project_logger.info(f"  ==> Found existing {self.query} results; skipping...")
            return
        if self.test_run:
            self.project_logger.info(f"  ==> Test run; skipping...")
            return

        # Step 1: Copy static query files if needed
        self.project_logger.info("  ==> Copying custom queries...")
        codeql_query_dir = f"{self.custom_codeql_root}/{self.query}"
        os.makedirs(codeql_query_dir, exist_ok=True)
        query_files = self.get_registered_query_files()
        for q in query_files:
            query_dest_path = f"{codeql_query_dir}/{q.split('/')[-1]}"
            if self.overwrite or self.overwrite_cwe_query_result or not os.path.exists(query_dest_path):
                shutil.copy(f"{THIS_SCRIPT_DIR}/{q}", query_dest_path)
            self.project_logger.info(f"  ==> Query {q.split('/')[-1]} ready... Done!")

        # Step 2: Run codeql analyze and produce sarif and csv
        self.project_logger.info("  ==> Running CodeQL analysis...")

        # Ensure CodeQL packs are installed for the custom 'iris' pack
        try:
            sp.run([CODEQL, "pack", "install"], cwd=self.custom_codeql_root, check=False)
        except Exception as e:
            self.project_logger.error(f"  ==> Failed during 'codeql pack install': {e}; aborting"); return
        lock_file_path = f"{self.custom_codeql_root}/codeql-pack.lock.yml"
        if not os.path.exists(lock_file_path):
            self.project_logger.error("  ==> Failed to install CodeQL packs (missing codeql-pack.lock.yml); aborting"); return
        query_filename = query_files[0].split("/")[-1]
        to_run_query_full_path = f"{codeql_query_dir}/{query_filename}"

        # Add search paths for both the built-in CodeQL packs and our custom pack
        search_paths = [
            f"{CODEQL_DIR}/qlpacks",  # Built-in CodeQL packs
            self.custom_codeql_root   # Our custom qlpack root
        ]
        search_path_args = []
        for path in search_paths:
            search_path_args.extend(["--search-path", path])

        # Run SARIF analysis
        sarif_cmd = [CODEQL, "database", "analyze", "--rerun"] + search_path_args + [
            self.project_codeql_db_path, "--format=sarif-latest", 
            f"--output={self.query_output_result_sarif_path}", to_run_query_full_path
        ]
        sp.run(sarif_cmd)
        if not os.path.exists(self.query_output_result_sarif_path):
            self.project_logger.error("  ==> Result SARIF not produced; aborting"); return

        # Run CSV analysis  
        csv_cmd = [CODEQL, "database", "analyze", "--rerun"] + search_path_args + [
            self.project_codeql_db_path, "--format=csv", 
            f"--output={self.query_output_result_csv_path}", to_run_query_full_path
        ]
        sp.run(csv_cmd)
        if not os.path.exists(self.query_output_result_csv_path):
            self.project_logger.error("  ==> Result CSV not produced; aborting"); return

    def extract_class_locations(self):
        if not os.path.exists(self.class_locs_path):
            self.project_logger.info(f"  ==> Class locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_class_locs")

    def extract_func_locations(self):
        if not os.path.exists(self.func_locs_path):
            self.project_logger.info(f"  ==> Function locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_func_locs")

    def extract_enclosing_decl_locs_map(self, decl_locs):
        """
        Extract enclosing declaration locations mapping from a pandas DataFrame

        :param decl_locs, a pandas DataFrame containing function or class locations
        :returns a mapping from file name to list of declarations defined in that file.
                 each declaration is a tuple (<decl_name>, <start_line>, <end_line>)
        """
        enclosing_decl_locs = {}
        for (i, row) in decl_locs.iterrows():
            if row["file"] not in enclosing_decl_locs:
                enclosing_decl_locs[row["file"]] = []
            enclosing_decl_locs[row["file"]].append((row["name"], row["start_line"], row["end_line"]))
        return enclosing_decl_locs

    def find_enclosing_declaration(self, start_line, end_line, decl_locs):
        closest_start_end = None
        for decl_loc in decl_locs:
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None:
                    closest_start_end = decl_loc
                else:
                    if decl_loc[1] > closest_start_end[1]:
                        closest_start_end = decl_loc
        return closest_start_end

    def is_valid_alarm(self, alarm):
        if "codeFlows" not in alarm:
            return False
        else:
            return len(alarm["codeFlows"]) > 0

    def get_source_line(self, location):
        relative_file_url = location["location"]["physicalLocation"]["artifactLocation"]["uri"]
        line_num = location["location"]["physicalLocation"]["region"]["startLine"]
        file_dir = f"{self.project_source_code_dir}/{relative_file_url}"
        if not os.path.exists(file_dir):
            print("Not found ", file_dir)
            return ""
        else:
            file_lines = list(open(file_dir, 'r').readlines())
            if line_num > len(file_lines):
                return ""
            else:
                line = file_lines[line_num - 1]
                return line

    def is_valid_code_flow(self, code_flow, source_is_func_param, project_methods):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
    
        # if source_is_func_param:
        #     source_loc = locations[0]
        #     source_file_url = source_loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
        #     source_start_line = source_loc["location"]["physicalLocation"]["region"]["startLine"]
        #     source_enclosing_func = self.find_enclosing_declaration(source_start_line, source_start_line, project_methods[source_file_url])

        snk_line = self.get_source_line(locations[-1])
        if ".println(" in snk_line or ".print(" in snk_line:
            return False

        for loc in locations:
            file_url = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
            if "src/test" in file_url:
                return False

        return True

    def post_process_cwe_query_result(self):
        self.project_logger.info("==> Stage 7: Post-processing CWE query results...")
        if self.language != "java":
            self.project_logger.info("  ==> Using native-language post-processing passthrough...")
            if not os.path.exists(self.query_output_result_sarif_path):
                self.project_logger.error("  ==> Result SARIF not found; skipping post-processing...")
                return
            if not self.test_run:
                shutil.copy(self.query_output_result_sarif_path, self.query_output_result_sarif_pp_path)
            return

        original_result_sarif = json.load(open(self.query_output_result_sarif_path))
        alarms = original_result_sarif["runs"][0]["results"]

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_func_locations()
        project_methods = self.extract_enclosing_decl_locs_map(pd.read_csv(self.func_locs_path))

        # 2. Print statistics
        num_alarms = len(alarms)
        num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> Original #alarms: {num_alarms}; Original #paths: {num_paths}")

        # Do a few things
        # 1. remove the paths with node location containing `src/test`
        # 2. if the path starts with a function parameter of `f`, and that the path
        #    contains anything after a `return` statement inside that function `f`
        for alarm in alarms:
            source_is_func_param = "user-provided value as public function parameter" in alarm["message"]["text"]
            if "codeFlows" in alarm:
                alarm["codeFlows"] = [cf for cf in alarm["codeFlows"] if self.is_valid_code_flow(cf, source_is_func_param, project_methods)]

        # 3. Remove the alarms with no code-flows
        alarms = [alarm for alarm in alarms if self.is_valid_alarm(alarm)]
        new_num_alarms = len(alarms)
        new_num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> New #alarms: {new_num_alarms}; New #paths: {new_num_paths}")

        # 4. Save the result back to the sarif
        original_result_sarif["runs"][0]["results"] = alarms
        if not self.test_run:
            json.dump(original_result_sarif, open(self.query_output_result_sarif_pp_path, "w"))

    def query_gpt_for_posthoc_filtering(self):
        self.project_logger.info("==> Stage 8: Querying GPT for posthoc filtering...")
        if self.skip_posthoc_filter:
            self.project_logger.info("  ==> Skipping posthoc filter...")
            return

        if self.language != "java":
            native_posthoc_pipeline = NativeContextualAnalysisPipeline(
                query=self.query,
                language=self.language,
                cwe_id=self.cwe_id,
                query_output_result_sarif_path=self.query_output_result_sarif_pp_path,
                posthoc_filtering_output_path=self.posthoc_filtering_output_path,
                project_source_code_dir=self.project_source_code_dir,
                project_logger=self.project_logger,
                llm=self.llm,
                batch_size=self.num_threads,
                overwrite=self.overwrite or self.overwrite_posthoc_filter,
                seed=self.seed,
                test_run=self.test_run,
            )
            native_posthoc_pipeline.run()
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Create and run the pipeline
        contextual_analysis_pipeline = ContextualAnalysisPipeline(
            self.query,
            self.cwe_id,
            self.llm,
            self.seed,
            self.class_locs_path,
            self.func_locs_path,
            self.project_fixed_methods,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_log_path,
            self.posthoc_filtering_output_result_json_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.posthoc_filtering_output_stats_json_path,
            self.project_source_code_dir,
            self.project_logger,
            self.overwrite,
            self.overwrite_posthoc_filter,
            self.test_run,
            posthoc_filtering_skip_fp=self.posthoc_filtering_skip_fp,
            rerun_skipped_fp=self.posthoc_filtering_rerun_skipped_fp,
        )
        contextual_analysis_pipeline.run()

    def build_evaluation_pipeline(self):
        return EvaluationPipeline(
            self.project_fixed_methods,
            self.class_locs_path,
            self.func_locs_path,
            self.project_source_code_dir,
            self.external_apis_csv_path,
            self.candidate_apis_csv_path,
            self.llm_labelled_sink_apis_path,
            self.llm_labelled_source_apis_path,
            self.llm_labelled_taint_prop_apis_path,
            self.source_func_param_candidates_path,
            self.llm_labelled_source_func_params_path,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.final_output_json_path,
            self.project_logger,
            overwrite=self.overwrite or self.overwrite_posthoc_filter or self.overwrite_cwe_query_result,
            test_run=self.test_run,
        )

    def evaluate_result(self):
        self.project_logger.info("==> Stage 9: Evaluating results...")
        if self.skip_evaluation or self.language != "java":
            self.project_logger.info("  ==> skipping evaluation...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Build
        eval_pipeline = self.build_evaluation_pipeline()
        eval_pipeline.run()

    def debug_result(self):
        if self.test_run:
            return
        if self.language != "java":
            return

        # Debug source information
        if self.debug_source:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sources/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sources...")
                self.run_simple_codeql_query("fetch_sources", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySources.qll": self.build_source_qll_with_enumeration()})

        # Debug sink information
        if self.debug_sink:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sinks/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sinks...")
                self.run_simple_codeql_query("fetch_sinks", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySinks.qll": self.build_sink_qll_with_enumeration()})

    def run(self):
        # Check if we need to continue running
        if os.path.exists(self.query_output_result_sarif_pp_path) and os.path.exists(self.posthoc_filtering_output_result_sarif_path) \
           and not self.overwrite and not self.overwrite_cwe_query_result \
           and not self.overwrite_postprocess_cwe_query_result \
           and not self.overwrite_posthoc_filter \
           and not self.posthoc_filtering_rerun_skipped_fp \
           or self.evaluation_only:
            self.master_logger.info(f"==> Cached final result found; skipping")
            self.post_process_cwe_query_result()
            self.evaluate_result()
            self.debug_result()
            exit(1)

        # 1. Collect all the invoked external APIs
        self.collect_invoked_external_apis()

        # 2. Collect all the internal function parameters
        self.collect_internal_function_parameters()

        # 3. Query GPT for source/taint-propagator/sink from external APIs
        self.query_gpt_for_api_src_tp_sink_batched()

        # 4. Query GPT for sources among internal function parameters
        self.query_gpt_for_func_param_src()

        # 5. Build local query for this project
        self.build_project_specific_query()

        # 6. Send the local query for vulnerability detection
        self.find_vulnerability()

        # 7. Do a post-processing step for rule-based filtering of paths
        self.post_process_cwe_query_result()

        # 8. Do posthoc filtering
        self.query_gpt_for_posthoc_filtering()

        # 9. Evaluate performance
        self.evaluate_result()

        # 10. Debuggging
        self.debug_result()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=str)
    parser.add_argument("--query", type=str, default="022", required=True)
    parser.add_argument("--llm", type=str, default="gpt-4")
    parser.add_argument("--language", choices=["java", "python", "cpp"], default="java")
    parser.add_argument("--run-id", type=str, default="default")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument("--num-threads", type=int, default=3)
    parser.add_argument("--no-summary-model", action="store_true")
    parser.add_argument("--use-exhaustive-qll", action="store_true")
    parser.add_argument("--filter-by-module", action="store_true")
    parser.add_argument("--filter-by-module-large", action="store_true")
    parser.add_argument("--skip-huge-project", action="store_true")
    parser.add_argument("--skip-huge-project-num-apis-threshold", type=int, default=3000)
    parser.add_argument("--skip-posthoc-filter", action="store_true")
    parser.add_argument("--skip-evaluation", action="store_true")
    parser.add_argument("--posthoc-filtering-skip-fp", action="store_true")
    parser.add_argument("--posthoc-filtering-rerun-skipped-fp", action="store_true")
    parser.add_argument("--evaluation-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--overwrite-api-candidates", action="store_true")
    parser.add_argument("--overwrite-func-param-candidates", action="store_true")
    parser.add_argument("--overwrite-labelled-apis", action="store_true")
    parser.add_argument("--overwrite-llm-cache", action="store_true")
    parser.add_argument("--overwrite-labelled-func-param", action="store_true")
    parser.add_argument("--overwrite-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-postprocess-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-posthoc-filter", action="store_true")
    parser.add_argument("--overwrite-debug-info", action="store_true")
    parser.add_argument("--debug-source", action="store_true")
    parser.add_argument("--debug-sink", action="store_true")
    parser.add_argument("--test-run", action="store_true")
    parser.add_argument("--use-container", action="store_true", help="Use container-built CodeQL database")
    args = parser.parse_args()

    # Set basic properties
    args.use_exhaustive_qll = True

    pipeline = SAPipeline(
        args.project,
        args.query,
        run_id=args.run_id,
        llm=args.llm,
        label_api_batch_size=args.label_api_batch_size,
        label_func_param_batch_size=args.label_func_param_batch_size,
        num_threads=args.num_threads,
        seed=args.seed,
        no_summary_model=args.no_summary_model,
        use_exhaustive_qll=args.use_exhaustive_qll,
        skip_huge_project=args.skip_huge_project,
        skip_huge_project_num_apis_threshold=args.skip_huge_project_num_apis_threshold,
        skip_posthoc_filter=args.skip_posthoc_filter,
        skip_evaluation=args.skip_evaluation,
        filter_by_module=args.filter_by_module,
        filter_by_module_large=args.filter_by_module_large,
        posthoc_filtering_skip_fp=args.posthoc_filtering_skip_fp,
        posthoc_filtering_rerun_skipped_fp=args.posthoc_filtering_rerun_skipped_fp,
        evaluation_only=args.evaluation_only,
        overwrite=args.overwrite,
        overwrite_api_candidates=args.overwrite_api_candidates,
        overwrite_func_param_candidates=args.overwrite_func_param_candidates,
        overwrite_labelled_apis=args.overwrite_labelled_apis,
        overwrite_llm_cache=args.overwrite_llm_cache,
        overwrite_labelled_func_param=args.overwrite_labelled_func_param,
        overwrite_cwe_query_result=args.overwrite_cwe_query_result,
        overwrite_postprocess_cwe_query_result=args.overwrite_postprocess_cwe_query_result,
        overwrite_posthoc_filter=args.overwrite_posthoc_filter,
        overwrite_debug_info=args.overwrite_debug_info,
        debug_source=args.debug_source,
        debug_sink=args.debug_sink,
        test_run=args.test_run,
        use_container=args.use_container,
        language=args.language,
    )

    pipeline.run()
