import json
import os
import shutil
import subprocess as sp
import argparse
from pathlib import Path

from src.config import CODEQL_DIR
from src.iris import SAPipeline


RUN_ID = "llm-multi-cwe-manual"
QUERIES = [
    "cwe-022wLLM",
    "cwe-079wLLM",
    "cwe-089wLLM",
    "cwe-094wLLM",
    "cwe-502wLLM",
    "cwe-918wLLM",
]


PY_SOURCE_INPUT = [
    {
        "package": "builtins",
        "class": "module",
        "method": "input",
        "signature": "input(prompt)",
        "type": "source",
    }
]


PY_CONFIG = {
    "cwe-022wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "builtins",
                "class": "module",
                "method": "open",
                "signature": "open(file, mode='r')",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [
            {
                "package": "os.path",
                "class": "module",
                "method": "os.path.join",
                "signature": "os.path.join(path, *paths)",
                "type": "taint-propagator",
            }
        ],
        "params": [],
    },
    "cwe-089wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "builtins",
                "class": "function",
                "method": "execute_query",
                "signature": "execute_query(query)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": [],
    },
    "cwe-079wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "application",
                "class": "function",
                "method": "send_html",
                "signature": "send_html(body)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": [],
    },
    "cwe-094wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "builtins",
                "class": "module",
                "method": "eval",
                "signature": "eval(expression, globals=None, locals=None)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": [],
    },
    "cwe-502wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "pickle",
                "class": "module",
                "method": "pickle.loads",
                "signature": "pickle.loads(data)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": [],
    },
    "cwe-918wLLM": {
        "sources": PY_SOURCE_INPUT,
        "sinks": [
            {
                "package": "urllib.request",
                "class": "module",
                "method": "urllib.request.urlopen",
                "signature": "urllib.request.urlopen(url, data=None)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": [],
    },
}


CPP_SOURCE_MAIN_ARGV = [
    {
        "package": "application",
        "class": "function",
        "method": "main",
        "signature": "main(argc;argv)",
        "tainted_input": ["argv"],
        "type": "source",
    }
]


CPP_SNPRINTF = [
    {
        "package": "libc",
        "class": "function",
        "method": "snprintf",
        "signature": "snprintf(buffer;size;format;...)",
        "type": "taint-propagator",
    }
]


CPP_CONFIG = {
    "cwe-022wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "libc",
                "class": "function",
                "method": "fopen",
                "signature": "fopen(path;mode)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": CPP_SNPRINTF,
        "params": CPP_SOURCE_MAIN_ARGV,
    },
    "cwe-089wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "sqlite3",
                "class": "function",
                "method": "sqlite3_exec",
                "signature": "sqlite3_exec(db;sql;callback;arg;errmsg)",
                "sink_args": ["p1"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": CPP_SOURCE_MAIN_ARGV,
    },
    "cwe-079wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "application",
                "class": "function",
                "method": "send_html",
                "signature": "send_html(body)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": CPP_SNPRINTF,
        "params": CPP_SOURCE_MAIN_ARGV,
    },
    "cwe-094wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "python-c-api",
                "class": "function",
                "method": "PyRun_SimpleString",
                "signature": "PyRun_SimpleString(command)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": CPP_SOURCE_MAIN_ARGV,
    },
    "cwe-502wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "application",
                "class": "function",
                "method": "deserialize_untrusted",
                "signature": "deserialize_untrusted(data)",
                "sink_args": ["p0"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": CPP_SOURCE_MAIN_ARGV,
    },
    "cwe-918wLLM": {
        "sources": [],
        "sinks": [
            {
                "package": "libcurl",
                "class": "function",
                "method": "curl_easy_setopt",
                "signature": "curl_easy_setopt(curl;option;parameter)",
                "sink_args": ["p2"],
                "type": "sink",
            }
        ],
        "steps": [],
        "params": CPP_SOURCE_MAIN_ARGV,
    },
}


PROJECTS = [
    ("iris-python-multi-cwe-smoke", "python", PY_CONFIG),
    ("iris-cpp-multi-cwe-smoke", "cpp", CPP_CONFIG),
]


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(value, f, indent=2)


def count_csv_rows(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return len([line for line in f.read().splitlines() if line.strip()])


def run_csv_only(pipe):
    codeql_query_dir = f"{pipe.custom_codeql_root}/{pipe.query}"
    Path(codeql_query_dir).mkdir(parents=True, exist_ok=True)
    for query_file in pipe.get_registered_query_files():
        dest = f"{codeql_query_dir}/{query_file.split('/')[-1]}"
        shutil.copy(f"{Path(__file__).parent.parent / 'src' / query_file}", dest)
    query_filename = pipe.get_registered_query_files()[0].split("/")[-1]
    query_path = f"{codeql_query_dir}/{query_filename}"
    sp.run([f"{CODEQL_DIR}/codeql", "pack", "install"], cwd=pipe.custom_codeql_root, check=False)
    search_path_args = []
    for path in [f"{CODEQL_DIR}/qlpacks", pipe.custom_codeql_root]:
        search_path_args.extend(["--search-path", path])
    cmd = [
        f"{CODEQL_DIR}/codeql",
        "database",
        "analyze",
        "--rerun",
        *search_path_args,
        pipe.project_codeql_db_path,
        "--format=csv",
        f"--output={pipe.query_output_result_csv_path}",
        query_path,
    ]
    sp.run(cmd, check=False)


def main():
    parser = argparse.ArgumentParser(description="Run multi-CWE LLM-route smoke checks with manual labels.")
    parser.add_argument("--language", choices=["python", "cpp"], default=None)
    parser.add_argument("--query", choices=QUERIES, default=None)
    args = parser.parse_args()

    for project, language, cfg in PROJECTS:
        if args.language and language != args.language:
            continue
        for query in QUERIES:
            if args.query and query != args.query:
                continue
            pipe = SAPipeline(
                project_name=project,
                query=query,
                run_id=RUN_ID,
                llm="cloud",
                language=language,
                use_exhaustive_qll=True,
                overwrite=True,
                overwrite_cwe_query_result=True,
                skip_posthoc_filter=True,
                skip_evaluation=True,
                num_threads=1,
            )
            labels = cfg[query]
            write_json(pipe.llm_labelled_source_apis_path, labels["sources"])
            write_json(pipe.llm_labelled_sink_apis_path, labels["sinks"])
            write_json(pipe.llm_labelled_taint_prop_apis_path, labels["steps"])
            write_json(pipe.llm_labelled_source_func_params_path, labels["params"])
            pipe.build_project_specific_query()
            run_csv_only(pipe)
            print(
                f"{project} {language} {query}: "
                f"{count_csv_rows(pipe.query_output_result_csv_path)} result rows "
                f"-> {pipe.query_output_result_csv_path}"
            , flush=True)


if __name__ == "__main__":
    main()
