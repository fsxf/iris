LANGUAGE_PROMPTS = {
    "python": {
        "api_system_prompt_replacements": {
            "package name": "module or package name",
            "class name": "class name, or \"module\" for module-level functions",
        },
        "function_param_system_prompt": """\
You are a security expert. \
You are given a list of Python functions implemented in the current project, \
and you need to identify whether some function parameters may carry malicious end-user input for vulnerability analysis. \
Treat parameters of public entry-point functions, web route handlers, CLI/helper wrappers, parsing/deserialization functions, and library APIs as potentially tainted when callers can pass user-controlled values. \
Ignore private helpers, test functions, constants, and parameters that are clearly not user-controlled. \
Return the result as a json list with each object in the format:

{ "package": <module or package name>,
  "class": <class name, or "module" for module-level functions>,
  "method": <function qualified name>,
  "signature": <signature>,
  "tainted_input": <a list of parameter names or p0/p1-style argument ids that are potentially tainted> }

Only keep functions whose parameters can plausibly be attacker-controlled. \
Do not output anything other than JSON.\
""",
        "function_param_user_prompt": """\
You are analyzing the Python project {project_username}/{project_name}. \
Here is the project summary:

{project_readme_summary}

Please look at the following Python functions and their documentations (if present). \
Identify function parameters that can plausibly receive malicious end-user input and therefore should be modeled as taint sources.
{cwe_hint}
If this project does not expose library functions, web handlers, command-line entry points, or other user-input boundaries, return an empty list.

Package,Class,Method,Signature,Doc
{methods}
""",
    },
    "cpp": {
        "api_system_prompt_replacements": {
            "package name": "library, namespace, or broad module name",
            "class name": "C/C++ class name, or \"function\" for free functions",
            "method name": "function name",
        },
        "function_param_system_prompt": """\
You are a security expert. \
You are given a list of C/C++ functions implemented in the current project, \
and you need to identify whether some function parameters may carry malicious end-user input for vulnerability analysis. \
Treat command-line entry points, public library APIs, request handlers, parser/deserializer entry points, callbacks, and wrapper functions as potentially tainted when callers can pass user-controlled values. \
For command-line programs, argv or parameters derived from argv are usually attacker-controlled. \
Ignore private helpers, tests, constants, and parameters that are clearly not user-controlled. \
Return the result as a json list with each object in the format:

{ "package": <library, namespace, or "cpp">,
  "class": <class name, or "function" for free functions>,
  "method": <function name>,
  "signature": <signature>,
  "tainted_input": <a list of parameter names or p0/p1-style argument ids that are potentially tainted> }

Only keep functions whose parameters can plausibly be attacker-controlled. \
Do not output anything other than JSON.\
""",
        "function_param_user_prompt": """\
You are analyzing the C/C++ project {project_username}/{project_name}. \
Here is the project summary:

{project_readme_summary}

Please look at the following C/C++ functions and their documentations (if present). \
Identify function parameters that can plausibly receive malicious end-user input and therefore should be modeled as taint sources.
{cwe_hint}
If this project does not expose command-line entry points, public library functions, request handlers, parsers, or other user-input boundaries, return an empty list.

Package,Class,Function,Signature,Doc
{methods}
""",
    },
}
