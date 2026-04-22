import ast
import copy
import csv
import json
import math
import os
import re

from tqdm import tqdm

from src.language_config import normalize_language
from src.models.llm import LLM
from src.prompts import (
    POSTHOC_FILTER_HINTS,
    POSTHOC_FILTER_LANGUAGE_HINTS,
    POSTHOC_FILTER_NATIVE_SYSTEM_PROMPT,
    POSTHOC_FILTER_NATIVE_USER_PROMPT,
    SNIPPET_CONTEXT_SIZE,
)


CPP_SOURCE_EXTENSIONS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")


class NativeContextualAnalysisPipeline:
    """LLM posthoc filtering for native CodeQL SARIF results.

    This mirrors the Java ContextualAnalysisPipeline shape: each CodeQL path is
    converted into source/intermediate/sink snippets, queried once per unique
    source/sink pair, and written back as filtered SARIF plus JSON logs.
    """

    def __init__(
            self,
            query,
            language,
            cwe_id,
            query_output_result_sarif_path,
            posthoc_filtering_output_path,
            project_source_code_dir,
            project_logger,
            llm="gpt-4",
            batch_size=1,
            overwrite=False,
            seed=1234,
            test_run=False,
    ):
        self.query = query
        self.language = normalize_language(language)
        self.display_language = "C/C++" if self.language == "cpp" else self.language.capitalize()
        self.cwe_id = cwe_id
        self.query_output_result_sarif_path = query_output_result_sarif_path
        self.posthoc_filtering_output_path = posthoc_filtering_output_path
        self.posthoc_filtering_output_log_path = os.path.join(posthoc_filtering_output_path, "logs")
        self.posthoc_filtering_output_result_json_path = os.path.join(posthoc_filtering_output_path, "results.json")
        self.posthoc_filtering_output_result_sarif_path = os.path.join(posthoc_filtering_output_path, "results.sarif")
        self.posthoc_filtering_output_result_csv_path = os.path.join(posthoc_filtering_output_path, "results.csv")
        self.posthoc_filtering_output_stats_json_path = os.path.join(posthoc_filtering_output_path, "stats.json")
        self.project_source_code_dir = project_source_code_dir
        self.project_logger = project_logger
        self.llm = llm
        self.batch_size = batch_size
        self.overwrite = overwrite
        self.seed = seed
        self.test_run = test_run
        self.model = None

        os.makedirs(self.posthoc_filtering_output_path, exist_ok=True)
        os.makedirs(self.posthoc_filtering_output_log_path, exist_ok=True)

    def get_model(self):
        if self.model is None:
            self.model = LLM.get_llm(
                model_name=self.llm,
                logger=self.project_logger,
                kwargs={"seed": self.seed, "max_new_tokens": 2048, "max_tokens": 2048},
            )
        return self.model

    def parse_boolean(self, value):
        if isinstance(value, str):
            if value.lower() == "true":
                return True
            if value.lower() == "false":
                return False
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        return value

    def parse_posthoc_filter_json_result(self, json_str):
        try:
            json_str = re.sub(r"```json\s*", "", json_str)
            json_str = re.sub(r"```\s*$", "", json_str)
            json_str = json_str.replace("\\'", "'")
            json_match = re.findall(r"\{[\s\S]*\}", json_str)
            if not json_match:
                self.project_logger.error("    ==> No JSON object found in response")
                return {}

            result = json.loads(json_match[0])
            if not isinstance(result, dict):
                return {}
            for key in ("is_vulnerable", "source_is_false_positive", "sink_is_false_positive"):
                if key in result:
                    result[key] = self.parse_boolean(result[key])
            return result
        except Exception as e:
            self.project_logger.error(f"    ==> Error parsing JSON: {e}")
            self.project_logger.error(f"    ==> Problematic JSON string: {repr(json_str[:500])}")
            return {}

    def sarif_location_to_path_loc(self, sarif_loc):
        location = sarif_loc.get("location", sarif_loc)
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})
        file_url = artifact.get("uri")
        if not file_url or "startLine" not in region:
            return None

        message = ""
        if "message" in location:
            message = location["message"].get("text", "")
        if not message and "message" in sarif_loc:
            message = sarif_loc["message"].get("text", "")
        if not message:
            message = "dataflow node"

        start_line = region["startLine"]
        return {
            "file_url": file_url,
            "start_line": start_line,
            "start_column": region.get("startColumn", 0),
            "end_line": region.get("endLine", start_line),
            "end_column": region.get("endColumn", region.get("startColumn", 0)),
            "message": message,
        }

    def iter_code_flows_for_query(self, sarif_json):
        rules = sarif_json["runs"][0].get("tool", {}).get("driver", {}).get("rules", [])
        for result_id, result in enumerate(sarif_json["runs"][0].get("results", [])):
            if "codeFlows" not in result:
                continue

            rule_description = self.describe_result_rule(result, rules)
            for code_flow_id, code_flow in enumerate(result["codeFlows"]):
                path_locations = []
                for thread_flow in code_flow.get("threadFlows", []):
                    for loc in thread_flow.get("locations", []):
                        path_loc = self.sarif_location_to_path_loc(loc)
                        if path_loc is not None:
                            path_locations.append(path_loc)
                path_locations = self.normalize_path_locations(path_locations)
                if path_locations:
                    yield (result_id, code_flow_id, path_locations, rule_description)

    def normalize_path_locations(self, path_locations):
        if self.language != "python":
            return path_locations
        normalized = list(path_locations)
        while len(normalized) > 1 and self.is_python_import_location(normalized[0]):
            normalized.pop(0)
        return normalized

    def is_python_import_location(self, loc):
        file_dir = os.path.join(self.project_source_code_dir, loc["file_url"])
        if not os.path.exists(file_dir):
            return False
        file_lines = open(file_dir, "r", encoding="utf-8", errors="replace").readlines()
        if loc["start_line"] - 1 >= len(file_lines):
            return False
        line = file_lines[loc["start_line"] - 1].strip()
        return line.startswith("import ") or line.startswith("from ")

    def describe_result_rule(self, result, rules):
        rule = {}
        rule_index = result.get("ruleIndex")
        if isinstance(rule_index, int) and 0 <= rule_index < len(rules):
            rule = rules[rule_index]
        rule_name = (
            rule.get("shortDescription", {}).get("text")
            or rule.get("properties", {}).get("name")
            or result.get("ruleId")
            or f"CWE-{self.cwe_id}"
        )
        return rule_name

    def iter_source_files(self):
        for root, _, files in os.walk(self.project_source_code_dir):
            for file_name in files:
                if self.language == "python" and file_name.endswith(".py"):
                    yield os.path.join(root, file_name)
                elif self.language == "cpp" and file_name.endswith(CPP_SOURCE_EXTENSIONS):
                    yield os.path.join(root, file_name)

    def relative_source_path(self, path):
        return os.path.relpath(path, self.project_source_code_dir).replace(os.sep, "/")

    def extract_enclosing_decl_locs(self):
        if self.language == "python":
            return self.extract_python_decl_locs()
        if self.language == "cpp":
            return self.extract_cpp_decl_locs()
        return {}

    def extract_python_decl_locs(self):
        result = {}
        for file_path in self.iter_source_files():
            rel_path = self.relative_source_path(file_path)
            try:
                source = open(file_path, "r", encoding="utf-8", errors="replace").read()
                tree = ast.parse(source)
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    end_line = getattr(node, "end_lineno", node.lineno)
                    result.setdefault(rel_path, []).append((node.name, node.lineno, end_line))
        return result

    def extract_cpp_decl_locs(self):
        tree_sitter_result = self.extract_cpp_decl_locs_with_tree_sitter()
        if tree_sitter_result:
            return tree_sitter_result

        self.project_logger.info("  ==> tree-sitter C/C++ parser unavailable or found no functions; falling back to heuristic parser...")
        return self.extract_cpp_decl_locs_with_regex()

    def extract_cpp_decl_locs_with_tree_sitter(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_c
            import tree_sitter_cpp
        except Exception:
            return {}

        parsers = {}

        def parser_for_path(file_path):
            ext = os.path.splitext(file_path)[1].lower()
            lang_module = tree_sitter_c if ext == ".c" else tree_sitter_cpp
            lang_key = "c" if ext == ".c" else "cpp"
            if lang_key not in parsers:
                language = Language(lang_module.language())
                parser = Parser()
                if hasattr(parser, "set_language"):
                    parser.set_language(language)
                else:
                    parser.language = language
                parsers[lang_key] = parser
            return parsers[lang_key]

        result = {}
        for file_path in self.iter_source_files():
            rel_path = self.relative_source_path(file_path)
            source_bytes = open(file_path, "rb").read()
            try:
                tree = parser_for_path(file_path).parse(source_bytes)
            except Exception:
                continue
            declarations = []
            self.collect_tree_sitter_cpp_decls(tree.root_node, source_bytes, declarations)
            if declarations:
                result[rel_path] = declarations
        return result

    def collect_tree_sitter_cpp_decls(self, node, source_bytes, declarations):
        if node.type == "function_definition":
            name = self.tree_sitter_function_name(node, source_bytes)
            declarations.append((name, node.start_point[0] + 1, node.end_point[0] + 1))
        elif node.type == "lambda_expression":
            declarations.append((f"lambda@{node.start_point[0] + 1}", node.start_point[0] + 1, node.end_point[0] + 1))

        for child in node.named_children:
            self.collect_tree_sitter_cpp_decls(child, source_bytes, declarations)

    def tree_sitter_function_name(self, node, source_bytes):
        declarator = node.child_by_field_name("declarator")
        name = self.tree_sitter_declarator_name(declarator, source_bytes)
        return name or f"function@{node.start_point[0] + 1}"

    def tree_sitter_declarator_name(self, node, source_bytes):
        if node is None:
            return None
        if node.type in {"identifier", "field_identifier", "operator_name", "destructor_name", "qualified_identifier"}:
            return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

        nested = node.child_by_field_name("declarator")
        nested_name = self.tree_sitter_declarator_name(nested, source_bytes)
        if nested_name:
            return nested_name

        for child in node.named_children:
            if child.type in {"parameter_list", "compound_statement"}:
                continue
            child_name = self.tree_sitter_declarator_name(child, source_bytes)
            if child_name:
                return child_name
        return None

    def extract_cpp_decl_locs_with_regex(self):
        result = {}
        func_re = re.compile(
            r"^\s*(?!if\b|for\b|while\b|switch\b|catch\b)"
            r"[\w:\<\>\~\*&,\s]+\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\([^;]*\)\s*(?:const\s*)?\{"
        )
        for file_path in self.iter_source_files():
            rel_path = self.relative_source_path(file_path)
            lines = open(file_path, "r", encoding="utf-8", errors="replace").readlines()
            i = 0
            while i < len(lines):
                match = func_re.match(lines[i])
                if not match:
                    i += 1
                    continue
                brace_balance = lines[i].count("{") - lines[i].count("}")
                end_idx = i
                while brace_balance > 0 and end_idx + 1 < len(lines):
                    end_idx += 1
                    brace_balance += lines[end_idx].count("{") - lines[end_idx].count("}")
                result.setdefault(rel_path, []).append((match.group(1), i + 1, end_idx + 1))
                i = end_idx + 1
        return result

    def find_enclosing_declaration(self, start_line, end_line, decl_locs):
        closest_start_end = None
        for decl_loc in decl_locs:
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None or decl_loc[1] > closest_start_end[1]:
                    closest_start_end = decl_loc
        return closest_start_end

    def path_location_to_enclose_func_and_msg(self, loc, enclosing_func_locs):
        file_url = loc["file_url"]
        if file_url in enclosing_func_locs:
            enclosing_func = self.find_enclosing_declaration(loc["start_line"], loc["end_line"], enclosing_func_locs[file_url])
            if enclosing_func:
                return f"{file_url}:{enclosing_func[0]}:{loc['message']}"
        return f"{file_url}#{loc['start_line']}:{loc['message']}"

    def comment_marker(self):
        return "#" if self.language == "python" else "//"

    def get_snippet_from_loc(self, loc, kind, enclosing_func_locs):
        file_dir = os.path.join(self.project_source_code_dir, loc["file_url"])
        if not os.path.exists(file_dir):
            self.project_logger.error(f"Not found {file_dir}")
            return ""

        file_lines = open(file_dir, "r", encoding="utf-8", errors="replace").readlines()
        start_line, end_line = loc["start_line"], loc["end_line"]
        func_start_end = None
        if loc["file_url"] in enclosing_func_locs:
            func_start_end = self.find_enclosing_declaration(start_line, end_line, enclosing_func_locs[loc["file_url"]])

        boundary_start, boundary_end = 0, len(file_lines)
        if func_start_end:
            boundary_start, boundary_end = func_start_end[1] - 1, func_start_end[2]

        snippet_start = max(start_line - 1 - SNIPPET_CONTEXT_SIZE, boundary_start)
        snippet_end = min(end_line + SNIPPET_CONTEXT_SIZE, boundary_end)
        start_ellipses = "...\n" if snippet_start > boundary_start else ""
        end_ellipses = "\n..." if snippet_end < boundary_end else ""

        marker = self.comment_marker()
        snippet = start_ellipses
        for idx in range(snippet_start, snippet_end):
            line = file_lines[idx].rstrip("\n")
            if start_line - 1 <= idx <= end_line - 1:
                snippet += f"{line}  {marker} <---- THIS IS THE {kind.upper()}\n"
            else:
                snippet += f"{line}\n"
        snippet += end_ellipses
        return snippet.rstrip()

    def intermediate_step_prompt(self, i, loc, enclosing_func_locs):
        file_name = loc["file_url"].split("/")[-1]
        file_dir = os.path.join(self.project_source_code_dir, loc["file_url"])
        if not os.path.exists(file_dir):
            return None
        file_lines = open(file_dir, "r", encoding="utf-8", errors="replace").readlines()
        if loc["start_line"] - 1 >= len(file_lines):
            return None
        line = file_lines[loc["start_line"] - 1].strip()

        func_name = ""
        if loc["file_url"] in enclosing_func_locs:
            enclosing = self.find_enclosing_declaration(loc["start_line"], loc["start_line"], enclosing_func_locs[loc["file_url"]])
            if enclosing is not None:
                func_name = f":{enclosing[0]}"

        message = f" ({loc['message']})" if loc.get("message") else ""
        return f"- Step {i + 1} [{file_name}{func_name}]{message}: {line}"

    def intermediate_steps_prompt(self, path_locs, enclosing_func_locs):
        step_size = max(1, math.floor(len(path_locs) / 10))
        trimmed_path_locs = path_locs[1:-1:step_size]
        steps = []
        for i, loc in enumerate(trimmed_path_locs):
            prompt = self.intermediate_step_prompt(i, loc, enclosing_func_locs)
            if prompt is not None:
                steps.append(prompt)
        return "\n".join(steps) if steps else "(No intermediate steps reported by CodeQL.)"

    def path_locs_to_user_prompt(self, path_locs, enclosing_func_locs, cwe_description):
        start_loc, end_loc = path_locs[0], path_locs[-1]
        source = self.get_snippet_from_loc(start_loc, "source", enclosing_func_locs)
        intermediate_steps = self.intermediate_steps_prompt(path_locs, enclosing_func_locs)
        sink = self.get_snippet_from_loc(end_loc, "sink", enclosing_func_locs)
        cwe_hint = POSTHOC_FILTER_HINTS.get(self.cwe_id, "")
        language_hint = POSTHOC_FILTER_LANGUAGE_HINTS.get(self.language, "")
        if cwe_hint:
            cwe_hint = f"CWE-specific note: {cwe_hint}"
        if language_hint:
            language_hint = f"Language-specific note: {language_hint}"

        return POSTHOC_FILTER_NATIVE_USER_PROMPT.format(
            language=self.display_language,
            cwe_description=cwe_description,
            cwe_id=f"CWE-{self.cwe_id}",
            hint=cwe_hint,
            language_hint=language_hint,
            source_msg=start_loc["message"],
            source=source,
            intermediate_steps=intermediate_steps,
            sink_msg=end_loc["message"],
            sink=sink,
        )

    def build_prompt_for_code_flow(self, path, enclosing_func_locs, cwe_description):
        path_user_prompt = self.path_locs_to_user_prompt(path, enclosing_func_locs, cwe_description)
        return [
            {"role": "system", "content": POSTHOC_FILTER_NATIVE_SYSTEM_PROMPT.format(language=self.display_language)},
            {"role": "user", "content": path_user_prompt},
        ]

    def use_cache_on_code_flow(self, result_id, path, enclosing_func_locs, grouped_path_cache, false_positive_source_cache, false_positive_sink_cache):
        source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
        sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
        group_id = (source, sink)

        if group_id in grouped_path_cache:
            return grouped_path_cache[group_id]
        if source in false_positive_source_cache and false_positive_source_cache[source]:
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": True,
                "sink_is_false_positive": false_positive_sink_cache.get(sink),
                "explanation": "[Caching] Source is marked false positive in a previous call to LLM",
            }
            grouped_path_cache[group_id] = result
            return result
        if sink in false_positive_sink_cache and false_positive_sink_cache[sink]:
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": false_positive_source_cache.get(source),
                "sink_is_false_positive": True,
                "explanation": "[Caching] Sink is marked false positive in a previous call to LLM",
            }
            grouped_path_cache[group_id] = result
            return result
        return None

    def batched_query_on_code_flow(self, entries, enclosing_func_locs, grouped_path_cache, false_positive_source_cache, false_positive_sink_cache):
        prompts = [
            self.build_prompt_for_code_flow(path, enclosing_func_locs, cwe_description)
            for (_, _, path, cwe_description) in entries
        ]

        for ((result_id, code_flow_id, _, _), prompt) in zip(entries, prompts):
            with open(f"{self.posthoc_filtering_output_log_path}/raw_user_prompt_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(prompt[1]["content"])

        if self.test_run:
            test_result = {
                "is_vulnerable": False,
                "source_is_false_positive": False,
                "sink_is_false_positive": False,
                "explanation": "[Test run] Prompt generated successfully; LLM call skipped.",
            }
            results = [json.dumps(test_result) for _ in prompts]
        else:
            try:
                results = self.get_model().predict(prompts, batch_size=self.batch_size, no_progress_bar=True)
            except Exception as e:
                self.project_logger.error(f"Error during LLM posthoc querying; skipping batch: {e}")
                results = ["" for _ in prompts]

        results_json = []
        for ((result_id, code_flow_id, path, _), prompt, result_str) in zip(entries, prompts, results):
            with open(f"{self.posthoc_filtering_output_log_path}/raw_llm_response_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(result_str)

            result_json = self.parse_posthoc_filter_json_result(result_str)
            source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
            sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
            group_id = (source, sink)

            grouped_path_cache[group_id] = result_json
            if result_json.get("source_is_false_positive"):
                false_positive_source_cache[source] = True
            if result_json.get("sink_is_false_positive"):
                false_positive_sink_cache[sink] = True

            results_json.append((
                result_id,
                code_flow_id,
                {
                    "path": path,
                    "using_cache": False,
                    "prompt": prompt[1]["content"],
                    "result": result_json,
                },
            ))
        return results_json

    def retain_sarif_json_with_code_flow_ids(self, original_sarif_json, predicted_is_vulnerable_path_ids):
        new_sarif_json = copy.deepcopy(original_sarif_json)
        new_results = []
        for result_id, old_result in enumerate(original_sarif_json["runs"][0].get("results", [])):
            if "codeFlows" not in old_result:
                continue
            new_result = copy.deepcopy(old_result)
            new_code_flows = []
            for code_flow_id, code_flow in enumerate(old_result["codeFlows"]):
                if (result_id, code_flow_id) in predicted_is_vulnerable_path_ids:
                    new_code_flows.append(code_flow)
            if new_code_flows:
                new_result["codeFlows"] = new_code_flows
                new_results.append(new_result)
        new_sarif_json["runs"][0]["results"] = new_results
        return new_sarif_json

    def dump_results_csv(self, code_flow_results):
        with open(self.posthoc_filtering_output_result_csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "result_id",
                    "code_flow_id",
                    "is_vulnerable",
                    "source_is_false_positive",
                    "sink_is_false_positive",
                    "using_cache",
                    "source",
                    "sink",
                    "explanation",
                ],
            )
            writer.writeheader()
            for item in code_flow_results:
                entry = item["entry"]
                result = entry.get("result", {})
                path = entry.get("path", [])
                writer.writerow({
                    "result_id": item["result_id"],
                    "code_flow_id": item["code_flow_id"],
                    "is_vulnerable": result.get("is_vulnerable"),
                    "source_is_false_positive": result.get("source_is_false_positive"),
                    "sink_is_false_positive": result.get("sink_is_false_positive"),
                    "using_cache": entry.get("using_cache"),
                    "source": self.format_loc(path[0]) if path else "",
                    "sink": self.format_loc(path[-1]) if path else "",
                    "explanation": result.get("explanation", ""),
                })

    def format_loc(self, loc):
        return f"{loc['file_url']}:{loc['start_line']}:{loc['start_column']}:{loc['message']}"

    def run(self):
        if os.path.exists(self.posthoc_filtering_output_result_sarif_path) and not self.overwrite:
            self.project_logger.info("  ==> Found existing native posthoc filter results; skipping...")
            return
        if not os.path.exists(self.query_output_result_sarif_path):
            self.project_logger.error("  ==> No SARIF result found for native posthoc filtering; aborting")
            return

        self.project_logger.info("  ==> Extracting native function locations...")
        enclosing_func_locs = self.extract_enclosing_decl_locs()

        self.project_logger.info("  ==> Loading native CodeQL SARIF...")
        original_sarif = json.load(open(self.query_output_result_sarif_path))

        grouped_path_cache, false_positive_source_cache, false_positive_sink_cache = {}, {}, {}
        num_processed, num_alerts, num_calls, num_cached, num_failure = 0, 0, 0, 0, 0
        code_flow_results, predicted_is_vulnerable_path_ids = [], []

        all_code_flows = list(self.iter_code_flows_for_query(original_sarif))
        to_query_batch = []
        iterator = tqdm(all_code_flows)
        for i, (result_id, code_flow_id, code_flow, cwe_description) in enumerate(iterator):
            iterator.set_description(
                f"#Processed: {num_processed}, #Alerts: {num_alerts}, #Calls: {num_calls}, #Cached: {num_cached}, #Fail: {num_failure}"
            )
            use_cache_result = self.use_cache_on_code_flow(
                result_id, code_flow, enclosing_func_locs,
                grouped_path_cache, false_positive_source_cache, false_positive_sink_cache,
            )
            if use_cache_result is not None:
                entry = {"path": code_flow, "prompt": "", "using_cache": True, "result": use_cache_result}
                code_flow_results.append({"result_id": result_id, "code_flow_id": code_flow_id, "entry": entry})
                num_processed += 1
                num_cached += 1
                if use_cache_result.get("is_vulnerable"):
                    num_alerts += 1
                    predicted_is_vulnerable_path_ids.append((result_id, code_flow_id))
                continue

            to_query_batch.append((result_id, code_flow_id, code_flow, cwe_description))
            if len(to_query_batch) == self.batch_size or i == len(all_code_flows) - 1:
                entries = self.batched_query_on_code_flow(
                    to_query_batch,
                    enclosing_func_locs,
                    grouped_path_cache,
                    false_positive_source_cache,
                    false_positive_sink_cache,
                )
                for result_id, code_flow_id, entry in entries:
                    code_flow_results.append({"result_id": result_id, "code_flow_id": code_flow_id, "entry": entry})
                    num_processed += 1
                    num_calls += 1
                    result = entry["result"]
                    if "is_vulnerable" in result:
                        if result["is_vulnerable"]:
                            num_alerts += 1
                            predicted_is_vulnerable_path_ids.append((result_id, code_flow_id))
                    else:
                        num_failure += 1
                to_query_batch = []

        json.dump(code_flow_results, open(self.posthoc_filtering_output_result_json_path, "w"))
        modified_sarif = self.retain_sarif_json_with_code_flow_ids(original_sarif, predicted_is_vulnerable_path_ids)
        json.dump(modified_sarif, open(self.posthoc_filtering_output_result_sarif_path, "w"))
        self.dump_results_csv(code_flow_results)
        stats = {
            "num_gpt_calls": num_calls,
            "num_cached": num_cached,
            "num_failure": num_failure,
            "num_vulnerable_paths": num_alerts,
            "num_processed_paths": num_processed,
        }
        json.dump(stats, open(self.posthoc_filtering_output_stats_json_path, "w"))
