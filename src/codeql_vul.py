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
NEUROSYMSA_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../")
sys.path.append(NEUROSYMSA_ROOT_DIR)

from src.config import CODEQL_DIR, CODEQL_DB_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR, IRIS_ROOT_DIR
from src.language_config import get_language_config, normalize_language, resolve_cwe_query_dir


from src.logger import Logger
from src.queries import QUERIES
from src.prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT
from src.prompts import FUNC_PARAM_LABELLING_SYSTEM_PROMPT, FUNC_PARAM_LABELLING_USER_PROMPT
from src.prompts import POSTHOC_FILTER_SYSTEM_PROMPT, POSTHOC_FILTER_USER_PROMPT, POSTHOC_FILTER_HINTS, SNIPPET_CONTEXT_SIZE
from src.codeql_queries import QL_SOURCE_PREDICATE, QL_STEP_PREDICATE, QL_SINK_PREDICATE
from src.codeql_queries import EXTENSION_YML_TEMPLATE, EXTENSION_SRC_SINK_YML_ENTRY, EXTENSION_SUMMARY_YML_ENTRY
from src.codeql_queries import QL_METHOD_CALL_SOURCE_BODY_ENTRY, QL_FUNC_PARAM_SOURCE_ENTRY, QL_FUNC_PARAM_NAME_ENTRY
from src.codeql_queries import QL_SUMMARY_BODY_ENTRY, QL_BODY_OR_SEPARATOR
from src.codeql_queries import QL_SINK_BODY_ENTRY, QL_SINK_ARG_NAME_ENTRY, QL_SINK_ARG_THIS_ENTRY

from src.modules.codeql_query_runner import CodeQLQueryRunner
from src.modules.evaluation_pipeline import EvaluationPipeline
from src.modules.native_contextual_analysis_pipeline import NativeContextualAnalysisPipeline


CODEQL_QUERY_NAME_RE = re.compile(r"^cwe-(?P<cwe_id>\d{2,4})wCodeQL(?P<variant>Exp|Custom)?$")
CUSTOM_CODEQL_QUERY_ROOT = os.path.join(IRIS_ROOT_DIR, "src", "native-codeql-queries")


def resolve_codeql_query_metadata(query: str) -> dict:
    if query in QUERIES:
        query_metadata = QUERIES[query]
        if "cwe_id" not in query_metadata:
            raise ValueError(f"Query `{query}` is not a query for detecting CWE")
        if query_metadata.get("type") != "codeql-query":
            raise ValueError(f"Query `{query}` is not a native CodeQL query")
        return {
            "name": query_metadata.get("name", query),
            "cwe_id": query_metadata["cwe_id"],
            "experimental": query_metadata.get("experimental", False),
            "registered": True,
        }

    match = CODEQL_QUERY_NAME_RE.match(query)
    if not match:
        raise ValueError(f"Unknown query `{query}`")

    return {
        "name": query,
        "cwe_id": match.group("cwe_id"),
        "experimental": match.group("variant") == "Exp",
        "custom": match.group("variant") == "Custom",
        "registered": False,
    }


def get_custom_codeql_query_dir(language: str, cwe_id: str) -> str:
    return os.path.join(CUSTOM_CODEQL_QUERY_ROOT, normalize_language(language), f"cwe-{cwe_id}")


class CodeQLSAPipeline:
    def __init__(
            self,
            project_name: str,
            query: str,
            language: str = "java",
            evaluation_only: bool = False,
            skip_evaluation: bool = False,
            overwrite: bool = False,
            llm_posthoc_filter: bool = False,
            posthoc_filter_only: bool = False,
            llm: str = "cloud",
            posthoc_batch_size: int = 1,
            seed: int = 1234,
            posthoc_test_run: bool = False,
    ):
        # Store basic information
        self.project_name = project_name
        self.query = query
        self.language = normalize_language(language)
        self.language_config = get_language_config(self.language)
        self.evaluation_only = evaluation_only
        self.skip_evaluation = skip_evaluation or self.language != "java"
        self.overwrite = overwrite
        self.llm_posthoc_filter = llm_posthoc_filter
        self.posthoc_filter_only = posthoc_filter_only
        self.llm = llm
        self.posthoc_batch_size = posthoc_batch_size
        self.seed = seed
        self.posthoc_test_run = posthoc_test_run

        # Setup logger
        self.master_logger = Logger(f"{IRIS_ROOT_DIR}/log")

        # Check if the query is valid
        try:
            self.query_metadata = resolve_codeql_query_metadata(self.query)
        except ValueError as e:
            self.master_logger.info(f"Processing {self.project_name} (Query: {self.query})...")
            self.master_logger.error(f"==> {e}; aborting"); exit(1)
        self.cwe_id = self.query_metadata["cwe_id"]
        self.experimental = self.query_metadata["experimental"]
        self.custom_query = self.query_metadata.get("custom", False)

        if not self.skip_evaluation:
            # Load some basic information, such as commits and fixes related to the CVE.
            # This metadata currently belongs to CWE-Bench-Java, so it is only used for
            # the Java evaluation path.
            self.cve_id = project_name.split("_")[3]
            self.all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)
            self.project_cve_with_commit_info = self.all_cves_with_commit[self.all_cves_with_commit["cve"] == self.cve_id].iloc[0]
            self.cve_fixing_commits = self.project_cve_with_commit_info["commits"].split(";")
            self.fixed_methods = pd.read_csv(ALL_METHOD_INFO_DIR)
            self.project_fixed_methods = self.fixed_methods[self.fixed_methods["db_name"] == self.project_name]
        else:
            self.project_fixed_methods = None
        self.project_source_code_dir = f"{PROJECT_SOURCE_CODE_DIR}/{self.project_name}"

        # Basic path information
        output_suffix = "common" if self.language == "java" else f"codeql-{self.language}"
        self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/{output_suffix}"

        # Setup codeql database path
        self.project_codeql_db_path = f"{CODEQL_DB_PATH}/{self.project_name}"
        if not os.path.exists(f"{self.project_codeql_db_path}/{self.language_config.database_subdir}"):
            self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}...")
            self.master_logger.error(f"==> Cannot find CodeQL database for {self.project_name}; aborting"); exit(1)

        # Setup query output path
        self.query_output_path = f"{self.project_output_path}/{self.query}"
        os.makedirs(self.query_output_path, exist_ok=True)
        self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"
        self.final_output_json_path = f"{self.query_output_path}/results.json"
        self.native_posthoc_filtering_output_path = f"{self.query_output_path}/posthoc-filter"

        # Function and Class locations
        self.func_locs_path = f"{self.project_output_path}/fetch_func_locs/results.csv"
        self.class_locs_path = f"{self.project_output_path}/fetch_class_locs/results.csv"

    def run_codeql_query(self):
        self.master_logger.info("==> Stage 1: Running CodeQL queries...")

        if self.custom_query:
            query_dir = get_custom_codeql_query_dir(self.language, self.cwe_id)
            self.master_logger.info(f"  ==> Using custom CodeQL query directory: {query_dir}")
        else:
            query_resolution = resolve_cwe_query_dir(CODEQL_DIR, self.language, self.cwe_id, self.experimental)
            query_dir = query_resolution.query_dir
            if query_resolution.fallback_to_experimental:
                self.master_logger.info(
                    f"  ==> Stable CodeQL query not found; falling back to experimental query: {query_dir}"
                )
            elif query_resolution.experimental:
                self.master_logger.info(f"  ==> Using experimental CodeQL query: {query_dir}")
        if not os.path.exists(query_dir):
            self.master_logger.error(f"==> Cannot find CodeQL query directory `{query_dir}`; aborting"); exit(1)

        cmd = [
            f"{CODEQL_DIR}/codeql",
            "database",
            "analyze",
            self.project_codeql_db_path,
            query_dir
        ]

        if self.overwrite:
            cmd += ["--rerun"]

        sp.run(cmd + [f"--output={self.query_output_result_sarif_path}", "--format=sarif-latest"])

        sp.run(cmd + [f"--output={self.query_output_result_csv_path}", "--format=csv"])

    def run_simple_codeql_query(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        runner = CodeQLQueryRunner(self.project_output_path, self.project_codeql_db_path, self.master_logger)
        runner.run(query, target_csv_path, suffix, dyn_queries)

    def extract_class_locations(self):
        if not os.path.exists(self.class_locs_path):
            self.master_logger.info(f"  ==> Class locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_class_locs")

    def extract_func_locations(self):
        if not os.path.exists(self.func_locs_path):
            self.master_logger.info(f"  ==> Function locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_func_locs")

    def build_evaluation_pipeline(self):
        return EvaluationPipeline(
            self.project_fixed_methods,
            self.class_locs_path,
            self.func_locs_path,
            self.project_source_code_dir,
            query_output_result_sarif_path=self.query_output_result_sarif_path,
            final_output_json_path=self.final_output_json_path,
            overwrite=self.overwrite,
            project_logger=self.master_logger,
        )

    def evaluate_result(self):
        if self.skip_evaluation:
            self.master_logger.info("==> Stage 2: Skipping evaluation for non-Java/native CodeQL run...")
            return

        self.master_logger.info("==> Stage 2: Evaluating results...")

        # 1. Extract class and function locations
        self.master_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Build
        self.master_logger.info("  ==> Evaluating results...")
        eval_pipeline = self.build_evaluation_pipeline()
        eval_pipeline.run_vanilla_only()

    def build_native_posthoc_pipeline(self):
        return NativeContextualAnalysisPipeline(
            query=self.query,
            language=self.language,
            cwe_id=self.cwe_id,
            query_output_result_sarif_path=self.query_output_result_sarif_path,
            posthoc_filtering_output_path=self.native_posthoc_filtering_output_path,
            project_source_code_dir=self.project_source_code_dir,
            project_logger=self.master_logger,
            llm=self.llm,
            batch_size=self.posthoc_batch_size,
            overwrite=self.overwrite,
            seed=self.seed,
            test_run=self.posthoc_test_run,
        )

    def query_llm_for_native_posthoc_filtering(self):
        if self.language == "java":
            self.master_logger.error("==> Native posthoc filtering is intended for non-Java native CodeQL runs; aborting"); exit(1)
        self.master_logger.info("==> Stage 3: Querying LLM for native posthoc filtering...")
        posthoc_pipeline = self.build_native_posthoc_pipeline()
        posthoc_pipeline.run()

    def run(self):
        if self.evaluation_only:
            if self.skip_evaluation:
                self.master_logger.error("==> Evaluation is currently only supported for the Java CWE-Bench pipeline; aborting"); exit(1)
            self.evaluate_result()
        elif self.posthoc_filter_only:
            self.query_llm_for_native_posthoc_filtering()
        else:
            self.run_codeql_query()
            self.evaluate_result()
            if self.llm_posthoc_filter:
                self.query_llm_for_native_posthoc_filtering()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=str)
    parser.add_argument("--query", type=str, default="cwe-022wCodeQL", required=True)
    parser.add_argument("--language", choices=["java", "python", "cpp"], default="java")
    parser.add_argument("--skip-evaluation", action="store_true",
                        help="Skip CWE-Bench-Java evaluation and only emit SARIF/CSV results")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--evaluation-only", action="store_true")
    parser.add_argument("--llm-posthoc-filter", action="store_true",
                        help="Run IRIS-style LLM posthoc filtering over native CodeQL SARIF results")
    parser.add_argument("--posthoc-filter-only", action="store_true",
                        help="Only run native LLM posthoc filtering over an existing SARIF result")
    parser.add_argument("--llm", type=str, default="cloud",
                        help="LLM used for native posthoc filtering")
    parser.add_argument("--posthoc-batch-size", type=int, default=1,
                        help="Batch size / worker count for native posthoc filtering")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--posthoc-test-run", action="store_true",
                        help="Build prompts and output empty posthoc results without calling the LLM")
    args = parser.parse_args()

    pipeline = CodeQLSAPipeline(
        args.project,
        args.query,
        language=args.language,
        evaluation_only=args.evaluation_only,
        skip_evaluation=args.skip_evaluation,
        overwrite=args.overwrite,
        llm_posthoc_filter=args.llm_posthoc_filter,
        posthoc_filter_only=args.posthoc_filter_only,
        llm=args.llm,
        posthoc_batch_size=args.posthoc_batch_size,
        seed=args.seed,
        posthoc_test_run=args.posthoc_test_run,
    )
    pipeline.run()
