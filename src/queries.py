"""
Registry format for QUERIES.

IRIS currently supports two broad query styles:

1. IRIS-style LLM queries (`type: "cwe-query"`)
   These collect project APIs/function parameters, ask an LLM to label
   sources/sinks/taint-propagators, generate project-specific QLL files, and
   then run a CWE-specific CodeQL query.

2. Native CodeQL queries (`type: "codeql-query"`)
   These run official or project-local CodeQL queries directly, optionally
   falling back to experimental or custom query packs.

Recommended shape for a multi-language IRIS-style query:

  "cwe-XXXwLLM": {
    "name": "cwe-XXXwLLM",
    "cwe_id": "XXX",             # zero-padded, for example "078"
    "cwe_id_short": "XX",        # non-padded, for example "78"
    "cwe_id_tag": "CWE-XX",
    "type": "cwe-query",
    "desc": "Short CWE description",

    # Backward-compatible Java default. Existing Java entries still use this.
    # New language-specific entries should prefer the `languages` block below.
    "queries": [
      "cwe-queries/java/cwe-XXX/main-query.ql",
      "cwe-queries/java/cwe-XXX/supporting-query.qll",
    ],

    # CWE-level information shared across languages. Stage 3 API labelling uses
    # `desc` and `long_desc` for Python/C++ as well as Java. `examples` remains
    # the Java/default examples unless a language overrides them.
    "prompts": {
      "cwe_id": "CWE-XXX",
      "desc": "Short CWE description",
      "long_desc": "Long CWE definition and attack pattern",
      "examples": [
        {
          "package": "...",
          "class": "...",
          "method": "...",
          "signature": "...",
          "sink_args": ["p0"],
          "type": "source | sink | taint-propagator",
        }
      ],
    },

    # Language-specific query files and prompt examples. This is where Python,
    # C/C++, and future languages should be added without duplicating the shared
    # CWE description above.
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-XXX/main-query.ql",
          "cwe-queries/python/cwe-XXX/supporting-query.qll",
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [...],
          "function_param_hint": "CWE-specific hint for parameter labelling",
        },
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-XXX/main-query.ql",
          "cwe-queries/cpp/cwe-XXX/supporting-query.qll",
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [...],
          "function_param_hint": "CWE-specific hint for parameter labelling",
        },
      },
    },
  }
"""
QUERIES = {
  "cwe-089wLLM": {
    "name": "cwe-089wLLM",
    "cwe_id": "089",
    "cwe_id_short": "89",
    "cwe_id_tag": "CWE-89",
    "type": "cwe-query",
    "desc": "SQL Injection via string concatenation",
    "queries": [
      "cwe-queries/java/cwe-089/cwe-089wLLM.ql",
      "cwe-queries/java/cwe-089/MySqlInjectionQuery.qll",
      "cwe-queries/java/cwe-089/MySqlConcatenatedLib.qll"
      ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-089/cwe-089wLLM.ql",
          "cwe-queries/python/cwe-089/MySqlInjectionQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "builtins",
              "class": "module",
              "method": "input",
              "signature": "input(prompt)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "sqlite3",
              "class": "Cursor",
              "method": "execute",
              "signature": "cursor.execute(sql, parameters=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "pymysql",
              "class": "Cursor",
              "method": "execute",
              "signature": "cursor.execute(query, args=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "str",
              "class": "str",
              "method": "format",
              "signature": "str.format(*args, **kwargs)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-089 SQL injection, focus on parameters that can influence SQL query text passed to execute/query APIs. Do not treat parameters used only as bound query parameters as vulnerable sinks."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-089/cwe-089wLLM.ql",
          "cwe-queries/cpp/cwe-089/MySqlInjectionQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "libc",
              "class": "function",
              "method": "getenv",
              "signature": "getenv(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "sqlite3",
              "class": "function",
              "method": "sqlite3_exec",
              "signature": "sqlite3_exec(db;sql;callback;arg;errmsg)",
              "sink_args": ["p1"],
              "type": "sink",
            },
            {
              "package": "mysqlclient",
              "class": "function",
              "method": "mysql_query",
              "signature": "mysql_query(mysql;query)",
              "sink_args": ["p1"],
              "type": "sink",
            },
            {
              "package": "libpq",
              "class": "function",
              "method": "PQexec",
              "signature": "PQexec(conn;query)",
              "sink_args": ["p1"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "sprintf",
              "signature": "sprintf(buffer;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-089 SQL injection, focus on parameters that can influence raw SQL query strings passed to sqlite3_exec, mysql_query, PQexec, or similar SQL execution APIs."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-089",
      "desc": "SQL Injection via string concatenation",
      "long_desc": """\
SQL Injection is a critical vulnerability that arises when user input is used to construct SQL queries without proper validation. \
This allows attackers to inject malicious SQL code into the query, bypass authentication, retrieve sensitive data, \
or execute arbitrary commands on the database server.\
This vulnerability occurs when applications dynamically build SQL strings using input from sources such as HTTP request parameters \
without using parameterized queries or prepared statements. Attackers can exploit this to perform unauthorized reads, data modification, or denial of service.
To address SQL injection, use parameterized queries, prepared statements, etc. Input validation, \
least privilege database access, and error message suppression are also important secondary defenses.
      """,
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HttpServletRequest",
          "method": "getParameter",
          "signature": "String getParameter(String name)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.sql",
          "class": "Statement",
          "method": "execute",
          "signature": "boolean execute(String sql)",
          "sink_args": ["sql"],
          "type": "sink"
        },
        {
          "package": "java.sql",
          "class": "Statement",
          "method": "executeQuery",
          "signature": "ResultSet executeQuery(String sql)",
          "sink_args": ["sql"],
          "type": "sink"
        },
        {
          "package": "java.lang",
          "class": "StringBuilder",
          "method": "append",
          "signature": "StringBuilder append(String str)",
          "sink_args": [],
          "type": "taint-propagator"
        }
      ]
    }
  },
  "cwe-089wCodeQL": {
    "name": "cwe-089wCodeQL",
    "cwe_id": "089",
    "cwe_id_short": "89",
    "cwe_id_tag": "CWE-89",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-022wLLM": {
    "name": "cwe-022wLLM",
    "type": "cwe-query",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "desc": "Path Traversal or Zip Slip",
    "queries": [
      "cwe-queries/java/cwe-022/cwe-022wLLM.ql",
      "cwe-queries/java/cwe-022/MyTaintedPathQuery.qll",
      "cwe-queries/java/cwe-022/PathCreation.qll",
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-022/cwe-022wLLM.ql",
          "cwe-queries/python/cwe-022/MyTaintedPathQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "flask",
              "class": "Request",
              "method": "args.get",
              "signature": "request.args.get(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "zipfile",
              "class": "ZipInfo",
              "method": "filename",
              "signature": "ZipInfo.filename",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "builtins",
              "class": "module",
              "method": "open",
              "signature": "open(file, mode='r')",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "os.path",
              "class": "module",
              "method": "join",
              "signature": "os.path.join(path, *paths)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-022 path traversal, focus on parameters that can influence filesystem paths, archive entry names, directory names, filenames, or paths passed to file open/read/write/extract APIs."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-022/cwe-022wLLM.ql",
          "cwe-queries/cpp/cwe-022/MyTaintedPathQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "libc",
              "class": "function",
              "method": "getenv",
              "signature": "getenv(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "fopen",
              "signature": "fopen(path;mode)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "posix",
              "class": "function",
              "method": "open",
              "signature": "open(path;flags)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "snprintf",
              "signature": "snprintf(buffer;size;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-022 path traversal, focus on C/C++ parameters that can influence filenames, directories, archive entry names, or paths passed to fopen, open, filesystem, archive extraction, or similar APIs."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-022",
      "desc": "Path Traversal or Zip Slip",
      "long_desc": """\
A path traversal vulnerability allows an attacker to access files \
on your web server to which they should not have access. They do this by tricking either \
the web server or the web application running on it into returning files that exist outside \
of the web root folder. Another attack pattern is that users can pass in malicious Zip file \
which may contain directories like "../". Typical sources of this vulnerability involves \
obtaining information from untrusted user input through web requests, getting entry directory \
from Zip files. Sinks will relate to file system manipulation, such as creating file, listing \
directories, and etc.""",
      "examples": [
        {
          "package": "java.util.zip",
          "class": "ZipEntry",
          "method": "getName",
          "signature": "String getName()",
            "sink_args": [],
          "type": "source",
        },
        {
          "package": "java.io",
          "class": "FileInputStream",
          "method": "FileInputStream",
          "signature": "FileInputStream(File file)",
          "sink_args" : ["file"],
          "type": "sink",
        },
        {
          "package": "java.net",
          "class": "URL",
          "method": "URL",
          "signature": "URL(String url)",
            "sink_args": [],
          "type": "taint-propagator",
        },
        {
            "package": "java.io",
            "class": "File",
            "method": "File",
            "signature": "File(String path)",
            "sink_args": [],
          "type": "taint-propagator",
        },
      ]
    }
  },
  "cwe-022wLLMSinksOnly": {
    "name": "cwe-022wLLMSinksOnly",
    "cwe_id": "022",
    "desc": "Path Traversal or Zip Slip",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/java/cwe-022/cwe-022wLLMSinksOnly.ql",
      "cwe-queries/java/cwe-022/MyTaintedPathQuery.qll",
    ],
  },
  "cwe-022wLLMSourcesOnly": {
    "name": "cwe-022wLLMSourcesOnly",
    "cwe_id": "022",
    "desc": "Path Traversal or Zip Slip",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/java/cwe-022/cwe-022wLLMSourcesOnly.ql",
      "cwe-queries/java/cwe-022/MyTaintedPathQuery.qll",
    ]
  },
  "cwe-022wCodeQL": {
    "name": "cwe-022wCodeQL",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-022wCodeQLExp": {
    "name": "cwe-022wCodeQLExp",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-078wLLM": {
    "name": "cwe-078wLLM",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "cwe-query",
    "desc": "OS Command Injection",
    "queries": [
      "cwe-queries/java/cwe-078/CommandInjectionRuntimeExecwLLM.ql",
      "cwe-queries/java/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/java/cwe-078/MyCommandArguments.qll",
      "cwe-queries/java/cwe-078/MyCommandLineQuery.qll",
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-078/cwe-078wLLM.ql",
          "cwe-queries/python/cwe-078/MyCommandInjectionQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "builtins",
              "class": "module",
              "method": "input",
              "signature": "input(prompt)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "os",
              "class": "module",
              "method": "system",
              "signature": "os.system(command)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "subprocess",
              "class": "module",
              "method": "Popen",
              "signature": "subprocess.Popen(args, ..., shell=False)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "subprocess",
              "class": "module",
              "method": "run",
              "signature": "subprocess.run(args, ..., shell=False)",
              "sink_args": ["p0"],
              "type": "sink",
            },
          ],
          "function_param_hint": "For CWE-078 OS command injection, focus on parameters that can reach command execution APIs, shell invocations, process creation APIs, or command strings built through concatenation/formatting."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-078/cwe-078wLLM.ql",
          "cwe-queries/cpp/cwe-078/MyCommandInjectionQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "stdlib",
              "class": "function",
              "method": "getenv",
              "signature": "getenv(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "system",
              "signature": "system(command)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "popen",
              "signature": "popen(command;type)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "sprintf",
              "signature": "sprintf(buffer;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-078 OS command injection, focus on C/C++ parameters that may receive user-controlled command strings or arguments, such as argv, network/request buffers, environment-derived values, and wrapper parameters later passed to system, popen, exec-family APIs, or command-building functions."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-078",
      "desc": "OS Command Injection",
      "long_desc": """\
OS command injection is also known as shell injection. It allows an \
attacker to execute operating system (OS) commands on the server that \
is running an application, and typically fully compromise the application \
and its data. Often, an attacker can leverage an OS command injection \
vulnerability to compromise other parts of the hosting infrastructure, \
and exploit trust relationships to pivot the attack to other systems within \
the organization.""",
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HTTPServletRequest",
          "method": "getCookies()",
          "signature": "Cookie[] getCookies()",
          "type": "source",
        },
        {
          "package": "java.lang",
          "class": "Runtime",
          "method": "exec",
          "signature": "Process exec(String[] cmdarray)",
          "sink_args": ["cmdarray"],
          "type": "sink",
        },
        {
          "package": "com.jcraft.jsch",
          "class": "ChannelExec",
          "method": "setCommand",
          "signature": "void setCommand(String command)",
          "sink_args": ["command"],
          "type": "sink",
        }
      ]
    }
  },
  #消融实验需求
  "cwe-078wLLMSinksOnly": {
    "name": "cwe-078wLLMSinksOnly",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "cwe-query-ablation",
    "desc": "OS Command Injection",
    "queries": [
      "cwe-queries/java/cwe-078/CommandInjectionRuntimeExecwLLMSinksOnly.ql",
      "cwe-queries/java/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/java/cwe-078/MyCommandArguments.qll",
      "cwe-queries/java/cwe-078/MyCommandLineQuery.qll",
    ]
   },
    "cwe-078wLLMSourcesOnly": {
    "name": "cwe-078wLLMSourcesOnly",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "desc": "OS Command Injection",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/java/cwe-078/CommandInjectionRuntimeExecwLLMSourcesOnly.ql",
      "cwe-queries/java/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/java/cwe-078/MyCommandArguments.qll",
      "cwe-queries/java/cwe-078/MyCommandLineQuery.qll",
    ]
   },
  "cwe-078wCodeQL": {
    "name": "cwe-078wCodeQL",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-078wCodeQLExp": {
    "name": "cwe-078wCodeQLExp",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-079wLLM": {
    "name": "cwe-079wLLM",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "cwe-query",
    "desc": "Cross-Site Scripting",
    "queries": [
      "cwe-queries/java/cwe-079/XSS.ql",
      "cwe-queries/java/cwe-079/MyXSS.qll",
      "cwe-queries/java/cwe-079/MyXssQuery.qll",
      "cwe-queries/java/cwe-079/MyXssLocalQuery.qll",
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-079/cwe-079wLLM.ql",
          "cwe-queries/python/cwe-079/MyXssQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "flask",
              "class": "Request",
              "method": "args.get",
              "signature": "request.args.get(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "flask",
              "class": "module",
              "method": "render_template_string",
              "signature": "render_template_string(source, **context)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "django.http",
              "class": "HttpResponse",
              "method": "HttpResponse",
              "signature": "HttpResponse(content='', *args, **kwargs)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "markupsafe",
              "class": "Markup",
              "method": "Markup",
              "signature": "Markup(base='')",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "str",
              "class": "str",
              "method": "format",
              "signature": "str.format(*args, **kwargs)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-079 XSS, focus on parameters that can influence HTML, JavaScript, template strings, response bodies, or values explicitly marked safe before being returned to a browser. Taint propagators should preserve data toward HTML/template/response output; do not label generic HTTP client APIs, file/network fetch APIs, or logging APIs as XSS propagators unless their return value is directly intended to be rendered into browser-visible content. Do not treat logging-only APIs as XSS sinks."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-079/cwe-079wLLM.ql",
          "cwe-queries/cpp/cwe-079/MyXssQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "application",
              "class": "function",
              "method": "main",
              "signature": "main(argc;argv)",
              "tainted_input": ["argv"],
              "type": "source",
            },
            {
              "package": "cgi",
              "class": "function",
              "method": "printf",
              "signature": "printf(format;...)",
              "sink_args": ["p1"],
              "type": "sink",
            },
            {
              "package": "cpp-httplib",
              "class": "Response",
              "method": "set_content",
              "signature": "set_content(body;content_type)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "snprintf",
              "signature": "snprintf(buffer;size;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-079 XSS, focus on parameters that can influence HTML, JavaScript, template output, HTTP response bodies, CGI output, or values written to browser-rendered content. Taint propagators should preserve data toward HTML/template/response output; do not label generic HTTP client APIs, file/network fetch APIs, or logging APIs as XSS propagators unless their return value is directly intended to be rendered into browser-visible content. Do not treat logging-only APIs as XSS sinks."
        }
      }
    },
    "prompts": {
      "cwe-id": "CWE-079",
      "desc": "Cross-Site Scripting",
      "long_desc": """\
Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable \
scripts into the code of a trusted application or website. Attackers often initiate an XSS \
attack by sending a malicious link to a user and enticing the user to click it. If the app \
or website lacks proper data sanitization, the malicious link executes the attacker's chosen \
code on the user's system. As a result, the attacker can steal the user's active session \
cookie. Logging functions are NOT sinks for XSS attacks.""",
      "examples": [
        {
          "package": "org.apache.wicket.core.request.handler",
          "class": "IPartialPageRequestHandler",
          "method": "appendJavaScript",
          "signature": "void appendJavaScript(CharSequence seq)",
          "sink_args": ["seq"],
          "type": "sink",
        },
        {
          "package": "org.thymeleaf",
          "class": "TemplateEngine",
          "method": "process",
          "signature": "void process(String template, IContext context, Writer writer)",
          "sink_args": ["context"],
          "type": "sink",
        },
        {
          "package": "org.jboss.resteasy.spi",
          "class": "HttpRequest",
          "method": "getDecodedFormParameters",
          "signature": "MultivaluedMap<String,String> getDecodedFormParameters()",
          "type": "source",
        },
      ]
    }
  },
  "cwe-079wLLMSinksOnly": {
    "name": "cwe-079wLLMSinksOnly",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "cwe-query-ablation",
    "desc": "Cross-Site Scripting",
    "queries": [
      "cwe-queries/java/cwe-079/XSSSinksOnly.ql",
      "cwe-queries/java/cwe-079/MyXSS.qll",
      "cwe-queries/java/cwe-079/MyXssQuery.qll",
      "cwe-queries/java/cwe-079/MyXssLocalQuery.qll",
    ]
  },
  "cwe-079wLLMSourcesOnly": {
    "name": "cwe-079wLLMSourcesOnly",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "desc": "Cross-Site Scripting",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/java/cwe-079/XSSSourcesOnly.ql",
      "cwe-queries/java/cwe-079/MyXSS.qll",
      "cwe-queries/java/cwe-079/MyXssQuery.qll",
      "cwe-queries/java/cwe-079/MyXssLocalQuery.qll",
    ]
  },
  "cwe-079wCodeQL": {
    "name": "cwe-079wCodeQL",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-079wCodeQLExp": {
    "name": "cwe-079wCodeQLExp",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-502wLLM": {
    "name": "cwe-502wLLM",
    "type": "cwe-query",
    "cwe_id": "502",
    "cwe_id_short": "502",
    "cwe_id_tag": "CWE-502",
    "desc": "Deserialization of Untrusted Data",
    "queries": [
      "cwe-queries/java/cwe-502/MyUnsafeDeserialization.ql",
      "cwe-queries/java/cwe-502/MyUnsafeDeserializationQuery.qll"
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-502/cwe-502wLLM.ql",
          "cwe-queries/python/cwe-502/MyUnsafeDeserializationQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "builtins",
              "class": "module",
              "method": "input",
              "signature": "input(prompt)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "pickle",
              "class": "module",
              "method": "loads",
              "signature": "pickle.loads(data, /, *, fix_imports=True, encoding='ASCII', errors='strict', buffers=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "yaml",
              "class": "module",
              "method": "load",
              "signature": "yaml.load(stream, Loader=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "marshal",
              "class": "module",
              "method": "loads",
              "signature": "marshal.loads(bytes)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "base64",
              "class": "module",
              "method": "b64decode",
              "signature": "base64.b64decode(s, altchars=None, validate=False)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-502 unsafe deserialization, focus on parameters that can influence serialized object bytes, YAML/XML/JSON payloads with type metadata, object graph data, or class/type descriptors passed to deserialization APIs. Do not treat safe JSON parsing into plain dictionaries/lists as a sink unless it instantiates attacker-controlled classes or types."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-502/cwe-502wLLM.ql",
          "cwe-queries/cpp/cwe-502/MyUnsafeDeserializationQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "application",
              "class": "function",
              "method": "main",
              "signature": "main(argc;argv)",
              "tainted_input": ["argv"],
              "type": "source",
            },
            {
              "package": "boost.serialization",
              "class": "archive",
              "method": "operator>>",
              "signature": "archive >> object",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "yaml-cpp",
              "class": "function",
              "method": "YAML::Load",
              "signature": "YAML::Load(input)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "protobuf",
              "class": "MessageLite",
              "method": "ParseFromString",
              "signature": "ParseFromString(data)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "snprintf",
              "signature": "snprintf(buffer;size;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-502 unsafe deserialization, focus on parameters that can influence serialized object buffers, archive streams, YAML/XML/JSON payloads with type metadata, object graph data, or attacker-controlled class/type descriptors passed to deserialization APIs. Do not treat simple parsing of inert data formats as a sink unless it can instantiate attacker-controlled objects, classes, or callbacks."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-502",
      "desc": "Deserialization of Untrusted Data",
      "long_desc": """\
        Deserialization of untrusted data occurs when an application deserializes input \
        without validating its origin or ensuring the safety of its content. An attacker \
        can exploit this to instantiate unexpected classes, invoke arbitrary methods, \
        or even trigger code execution via malicious object graphs or gadget chains. \
        This can lead to serious consequences such as unauthorized access, data corruption, \
        or remote code execution. Common mitigation strategies include using class allowlists, \
        avoiding unnecessary deserialization, making sensitive fields transient, and validating \
        object types before deserializing.""",
      "examples": [
        {
          "package": "java.io",
          "class": "ObjectInputStream",
          "method": "readObject",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        },
        {
          "package": "java.io",
          "class": "ByteArrayInputStream",
          "method": "ByteArrayInputStream",
          "signature": "ByteArrayInputStream(byte[] buf)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.beans",
          "class": "XMLDecoder",
          "method": "readObject",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        },
        {
          "package": "org.apache.commons.lang3",
          "class": "SerializationUtils",
          "method": "deserialize",
          "signature": "<T> T deserialize(byte[] objectData)",
          "sink_args": ["objectData"],
          "type": "sink"
        }
      ]
    }
  },
  "cwe-094wLLM": {
    "name": "cwe-094wLLM",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "desc": "Code Injection",
    "type": "cwe-query",
    "queries": [
      "cwe-queries/java/cwe-094/SpelInjection.ql",
      "cwe-queries/java/cwe-094/MySpelInjection.qll",
      "cwe-queries/java/cwe-094/MySpelInjectionQuery.qll",
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-094/cwe-094wLLM.ql",
          "cwe-queries/python/cwe-094/MyCodeInjectionQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "builtins",
              "class": "module",
              "method": "input",
              "signature": "input(prompt)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "builtins",
              "class": "module",
              "method": "eval",
              "signature": "eval(expression, globals=None, locals=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "builtins",
              "class": "module",
              "method": "exec",
              "signature": "exec(object, globals=None, locals=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "builtins",
              "class": "module",
              "method": "compile",
              "signature": "compile(source, filename, mode)",
              "sink_args": ["p0"],
              "type": "sink",
            },
          ],
          "function_param_hint": "For CWE-094 code injection, focus on parameters that can reach dynamic code evaluation APIs such as eval, exec, compile, expression evaluators, or template engines that interpret code-like input."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-094/cwe-094wLLM.ql",
          "cwe-queries/cpp/cwe-094/MyCodeInjectionQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "libc",
              "class": "function",
              "method": "getenv",
              "signature": "getenv(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "lua",
              "class": "function",
              "method": "luaL_dostring",
              "signature": "luaL_dostring(L;str)",
              "sink_args": ["p1"],
              "type": "sink",
            },
            {
              "package": "python-c-api",
              "class": "function",
              "method": "PyRun_SimpleString",
              "signature": "PyRun_SimpleString(command)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "sprintf",
              "signature": "sprintf(buffer;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-094 code injection, focus on parameters that can influence script strings, expression strings, dynamic evaluator inputs, or embedded interpreter APIs such as Lua/Python/JavaScript evaluation calls."
        }
      }
    },
    "prompts": {
      "cwe-id": "CWE-079",
      "desc": "Code Injection",
      "long_desc": """\
Code injection is the term used to describe attacks that inject code \
into an application. That injected code is then interpreted by the \
application, changing the way a program executes. Code injection attacks \
typically exploit an application vulnerability that allows the processing \
of invalid data. This type of attack exploits poor handling of untrusted \
data, and these types of attacks are usually made possible due to a lack \
of proper input/output data validation.""",
      "examples": [
        {
          "package": "com.datastax.driver.core",
          "class": "Session",
          "method": "execute",
          "signature": "void execute(String code, Object[] args)",
          "sink_args": ["code", "args"],
          "type": "sink",
        },
        {
          "package": "org.xmlunit.xpath",
          "class": "JAXPXPathEngine",
          "method": "evaluate",
          "signature": "String evaluate(String xPath, Node n)",
          "sink_args": ["xPath"],
          "type": "sink",
        },
        {
          "package": "javax.mail.internet",
          "class": "MimeMessage",
          "method": "getAllHeaders",
          "signature": "Enumeration<Header> getAllHeaders()",
          "type": "source",
        },
      ]
    }
  },
  "cwe-094wLLMSourcesOnly": {
    "name": "cwe-094wLLMSourcesOnly",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "desc": "Code Injection",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/java/cwe-094/SpelInjectionSourcesOnly.ql",
      "cwe-queries/java/cwe-094/MySpelInjection.qll",
      "cwe-queries/java/cwe-094/MySpelInjectionQuery.qll",
    ]
  },
   "cwe-094wLLMSinksOnly": {
    "name": "cwe-094wLLMSinksOnly",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "cwe-query-ablation",
    "desc": "Code Injection",
    "queries": [
      "cwe-queries/java/cwe-094/SpelInjectionSinksOnly.ql",
      "cwe-queries/java/cwe-094/MySpelInjection.qll",
      "cwe-queries/java/cwe-094/MySpelInjectionQuery.qll",
    ]
  },
  "cwe-094wCodeQL": {
    "name": "cwe-094wCodeQL",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-094wCodeQLExp": {
    "name": "cwe-094wCodeQLExp",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-918wLLM": {
    "name": "cwe-918wLLM",
    "cwe_id": "918",
    "cwe_id_short": "918",
    "cwe_id_tag": "CWE-918",
    "type": "cwe-query",
    "desc": "Server-Side Request Forgery (SSRF)",
    "queries": [
      "cwe-queries/java/cwe-918/cwe-918wLLM.ql",
      "cwe-queries/java/cwe-918/MyRequestForgeryQuery.qll"
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-918/cwe-918wLLM.ql",
          "cwe-queries/python/cwe-918/MyRequestForgeryQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "flask",
              "class": "Request",
              "method": "args.get",
              "signature": "request.args.get(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "requests",
              "class": "module",
              "method": "get",
              "signature": "requests.get(url, **kwargs)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "urllib.request",
              "class": "module",
              "method": "urlopen",
              "signature": "urllib.request.urlopen(url, data=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "urllib.parse",
              "class": "module",
              "method": "urljoin",
              "signature": "urllib.parse.urljoin(base, url)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-918 SSRF, focus on parameters that can influence outbound request URLs, hosts, schemes, paths, or request objects passed to HTTP client APIs."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-918/cwe-918wLLM.ql",
          "cwe-queries/cpp/cwe-918/MyRequestForgeryQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "libc",
              "class": "function",
              "method": "getenv",
              "signature": "getenv(name)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "libcurl",
              "class": "function",
              "method": "curl_easy_setopt",
              "signature": "curl_easy_setopt(curl;option;parameter)",
              "sink_args": ["p2"],
              "type": "sink",
            },
            {
              "package": "libcurl",
              "class": "function",
              "method": "curl_url_set",
              "signature": "curl_url_set(url;part;content;flags)",
              "sink_args": ["p2"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "snprintf",
              "signature": "snprintf(buffer;size;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-918 SSRF, focus on parameters that can influence outbound URLs, hosts, schemes, or request destination strings used by libcurl, HTTP clients, or socket/request helpers."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-918",
      "desc": "Server-Side Request Forgery (SSRF)",
      "long_desc": """\
Server-Side Request Forgery (SSRF) occurs when an application makes a network request
using a URL or host that is fully or partially controlled by user input. Attackers
can abuse this to make the server perform HTTP(S) or other protocol requests to
internal services, cloud metadata endpoints, or arbitrary external servers. This
can lead to sensitive information disclosure, port scanning, or further
pivoting within the infrastructure. Properly validate and sanitize any user
input that influences outbound request destinations, and employ allow-lists
or network egress filtering where possible.""",
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HttpServletRequest",
          "method": "getParameter",
          "signature": "String getParameter(String name)",
          "type": "source"
        },
        {
          "package": "org.apache.http.client",
          "class": "HttpClient",
          "method": "execute",
          "signature": "HttpResponse execute(HttpUriRequest request)",
          "sink_args": ["request"],
          "type": "sink"
        },
        {
          "package": "java.net",
          "class": "URL",
          "method": "URL",
          "signature": "URL(String spec)",
          "type": "taint-propagator"
        }
      ]
    }
  },
"cwe-807wLLM": {
    "name": "cwe-807wLLM",
    "type": "cwe-query",
    "cwe_id": "807",
    "cwe_id_short": "807",
    "cwe_id_tag": "CWE-807",
    "desc": "Reliance on Untrusted Inputs in a Security Decision",
    "queries": [
        "cwe-queries/java/cwe-807/cwe-807wLLM.ql",
        "cwe-queries/java/cwe-807/MyTaintedPermissionsCheckQuery.qll",
    ],
    "prompts": {
        "cwe_id": "CWE-807",
        "desc": "Reliance on Untrusted Inputs in a Security Decision",
        "long_desc": """\
CWE-807 refers that the product uses a protection mechanism that relies on the existence or values of an input, but the input can be modified by an untrusted actor in a way that bypasses the protection mechanism. If permission checks (such as Subject.isPermitted or similar APIs) receive tainted data, attackers may manipulate permission strings or resource identifiers to escalate privileges or access unauthorized resources. Sources are typically user-provided values (e.g., HTTP parameters), and sinks are permission check methods or constructors that determine access control.
""",
        "examples": [
            {
                "package": "javax.servlet.http",
                "class": "HttpServletRequest",
                "method": "getParameter",
                "signature": "String getParameter(String name)",
                "sink_args": [],
                "type": "source"
            },
            {
                "package": "org.apache.shiro.subject",
                "class": "Subject",
                "method": "isPermitted",
                "signature": "boolean isPermitted(String permission)",
                "sink_args": ["permission"],
                "type": "sink"
            },
            {
            "package": "java.util",
            "class": "HashMap",
            "method": "putAll",
            "signature": "void putAll(Map<? extends K,? extends V> m)",
            "propagator_args": ["m"],
            "type": "propagator"
            }
        ]
    }
},
"cwe-352wLLM": {
  "name": "cwe-352wLLM",
  "type": "cwe-query",
  "cwe_id": "352",
  "cwe_id_short": "352",
  "cwe_id_tag": "CWE-352",
  "desc": "Cross-Site Request Forgery",
  "queries": [
    "cwe-queries/java/cwe-352/cwe-352wLLM.ql",
    "cwe-queries/java/cwe-352/MyJsonpInjectionLib.qll",
    "cwe-queries/java/cwe-352/MyJsonStringLib.qll",
  ],
  "languages": {
    "python": {
      "queries": [
        "cwe-queries/python/cwe-352/cwe-352wLLM.ql",
        "cwe-queries/python/cwe-352/MyJsonpInjectionQuery.qll"
      ],
      "renderer": "python",
      "prompts": {
        "api_examples": [
          {
            "package": "builtins",
            "class": "module",
            "method": "input",
            "signature": "input(prompt)",
            "sink_args": [],
            "type": "source",
          },
          {
            "package": "flask",
            "class": "request",
            "method": "args.get",
            "signature": "flask.request.args.get(key, default=None, type=None)",
            "sink_args": [],
            "type": "source",
          },
          {
            "package": "application",
            "class": "function",
            "method": "send_jsonp",
            "signature": "send_jsonp(body)",
            "sink_args": ["p0"],
            "type": "sink",
          },
          {
            "package": "flask",
            "class": "module",
            "method": "Response",
            "signature": "flask.Response(response=None, status=None, headers=None, mimetype=None)",
            "sink_args": ["p0"],
            "type": "sink",
          },
          {
            "package": "builtins",
            "class": "str",
            "method": "format",
            "signature": "str.format(*args, **kwargs)",
            "sink_args": [],
            "type": "taint-propagator",
          },
        ],
        "function_param_hint": "For CWE-352 in this IRIS template, follow the Java JSONP Injection shape: focus on callback or function-name parameters that can be concatenated into a JavaScript/JSONP response such as callback + '(' + json + ')' and returned to a browser. Treat JSONP response writers or script-like response builders as sinks when the callback-bearing response body reaches them. Do not broaden this to generic CSRF token checks, ordinary HTML responses, redirects, or unrelated request handlers unless they construct JSONP/callback JavaScript from attacker-controlled input."
      }
    },
    "cpp": {
      "queries": [
        "cwe-queries/cpp/cwe-352/cwe-352wLLM.ql",
        "cwe-queries/cpp/cwe-352/MyJsonpInjectionQuery.qll"
      ],
      "renderer": "cpp",
      "prompts": {
        "api_examples": [
          {
            "package": "application",
            "class": "function",
            "method": "main",
            "signature": "main(argc;argv)",
            "tainted_input": ["argv"],
            "type": "source",
          },
          {
            "package": "application",
            "class": "function",
            "method": "send_jsonp",
            "signature": "send_jsonp(body)",
            "sink_args": ["p0"],
            "type": "sink",
          },
          {
            "package": "web-framework",
            "class": "function",
            "method": "send_response",
            "signature": "send_response(body)",
            "sink_args": ["p0"],
            "type": "sink",
          },
          {
            "package": "libc",
            "class": "function",
            "method": "snprintf",
            "signature": "snprintf(buffer;size;format;...)",
            "sink_args": [],
            "type": "taint-propagator",
          },
        ],
        "function_param_hint": "For CWE-352 in this IRIS template, follow the Java JSONP Injection shape: focus on callback or function-name parameters that can be formatted into JavaScript/JSONP response bodies such as \"%s({...})\" and returned to a browser. Treat response writer functions as sinks when the callback-bearing body reaches them. Do not broaden this to generic CSRF token checks, ordinary HTML responses, redirects, or unrelated handlers unless they construct JSONP/callback JavaScript from attacker-controlled input."
      }
    }
  },
  "prompts": {
    "cwe_id": "CWE-352",
    "desc": "Cross-Site Request Forgery (JSONP Injection)",
    "long_desc": """\
A Cross-Site Request Forgery (CSRF) vulnerability allows attackers to perform unauthorized actions on behalf of authenticated users. 
In Java web applications, insecure JSONP endpoints may be abused for CSRF or data exfiltration attacks if the callback parameter is not properly validated. 
Sources typically include untrusted HTTP request parameters (such as 'callback'). Sinks are points where JSONP responses are constructed and returned to the client without validation.""",
    "examples": [
      {
        "package": "javax.servlet.http",
        "class": "HttpServletRequest",
        "method": "getParameter",
        "signature": "String getParameter(String name)",
        "sink_args": [],
        "type": "source",
      },
      {
        "package": "javax.servlet.http",
        "class": "HttpServletResponse",
        "method": "getWriter",
        "signature": "PrintWriter getWriter()",
        "sink_args": [],
        "type": "sink",
      },
      {
        "package": "org.json",
        "class": "JSONObject",
        "method": "toString",
        "signature": "String toString()",
        "sink_args": [],
        "type": "taint-propagator",
      },
    ]
  }
},
"cwe-611wLLM": {
    "name": "cwe-611wLLM",
    "type": "cwe-query",
    "cwe_id": "611",
    "cwe_id_short": "611",
    "cwe_id_tag": "CWE-611",
    "desc": "Improper Restriction of XML External Entity Reference",
    "queries": [
      "cwe-queries/java/cwe-611/XXE.ql",
      "cwe-queries/java/cwe-611/MyXxeRemoteQuery.qll",
      "cwe-queries/java/cwe-611/MyXxeQuery.qll",
      "cwe-queries/java/cwe-611/MyXxe.qll"
    ],
    "languages": {
      "python": {
        "queries": [
          "cwe-queries/python/cwe-611/cwe-611wLLM.ql",
          "cwe-queries/python/cwe-611/MyXxeQuery.qll"
        ],
        "renderer": "python",
        "prompts": {
          "api_examples": [
            {
              "package": "builtins",
              "class": "module",
              "method": "input",
              "signature": "input(prompt)",
              "sink_args": [],
              "type": "source",
            },
            {
              "package": "xml.dom.minidom",
              "class": "module",
              "method": "parseString",
              "signature": "xml.dom.minidom.parseString(string, parser=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "lxml.etree",
              "class": "module",
              "method": "fromstring",
              "signature": "lxml.etree.fromstring(text, parser=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "xml.sax",
              "class": "module",
              "method": "parseString",
              "signature": "xml.sax.parseString(string, handler, errorHandler=None)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "base64",
              "class": "module",
              "method": "b64decode",
              "signature": "base64.b64decode(s, altchars=None, validate=False)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-611 XXE, focus on parameters that can influence XML document text, XML byte streams, parser input sources, DTD/entity definitions, or parser configuration passed to XML parsing APIs. Treat XML parsers that may load DTDs or resolve external entities as sinks. Do not treat safe XML serialization or XML output-only APIs as sinks."
        }
      },
      "cpp": {
        "queries": [
          "cwe-queries/cpp/cwe-611/cwe-611wLLM.ql",
          "cwe-queries/cpp/cwe-611/MyXxeQuery.qll"
        ],
        "renderer": "cpp",
        "prompts": {
          "api_examples": [
            {
              "package": "application",
              "class": "function",
              "method": "main",
              "signature": "main(argc;argv)",
              "tainted_input": ["argv"],
              "type": "source",
            },
            {
              "package": "libxml2",
              "class": "function",
              "method": "xmlReadMemory",
              "signature": "xmlReadMemory(buffer;size;url;encoding;options)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libxml2",
              "class": "function",
              "method": "xmlParseDoc",
              "signature": "xmlParseDoc(cur)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "xerces-c",
              "class": "XercesDOMParser",
              "method": "parse",
              "signature": "parse(source)",
              "sink_args": ["p0"],
              "type": "sink",
            },
            {
              "package": "libc",
              "class": "function",
              "method": "snprintf",
              "signature": "snprintf(buffer;size;format;...)",
              "sink_args": [],
              "type": "taint-propagator",
            },
          ],
          "function_param_hint": "For CWE-611 XXE, focus on parameters that can influence XML document buffers, XML byte streams, input sources, DTD/entity definitions, or parser configuration passed to XML parsing APIs such as libxml2, Xerces, Expat, or project XML parser wrappers. Treat parsers that may load DTDs or resolve external entities as sinks. Do not treat XML output-only APIs as sinks."
        }
      }
    },
    "prompts": {
      "cwe_id": "CWE-611",
      "desc": "Improper Restriction of XML External Entity Reference",
      "long_desc": """\
        XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities. It is possible to define an entity by providing a substitution string in the form of a URI. The XML parser can access the contents of this URI and embed these contents back into the XML document for further processing. \
By submitting an XML file that defines an external entity with a file:// URI, an attacker can cause the processing application to read the contents of a local file. For example, a URI such as "file:///c:/winnt/win.ini" designates (in Windows) the file C:\\Winnt\\win.ini, or file:///etc/passwd designates the password file in Unix-based systems. Using URIs with other schemes such as http://, the attacker can force the application to make outgoing requests to servers that the attacker cannot reach directly, which can be used to bypass firewall restrictions or hide the source of attacks such as port scanning.\
Once the content of the URI is read, it is fed back into the application that is processing the XML. This application may echo back the data (e.g. in an error message), thereby exposing the file contents.""",
      "examples": [ 
        {
          "package": "javax.xml.transform",
          "class": "DefaultDDFFileValidator",
          "method": "validate",
          "signature": "void validate(Source xmlToValidate)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.xml.parsers.DocumentBuilderFactory",
          "class": "DOMWalker",
          "method": "",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        }, 
      ]
    }
  },
  "cwe-295wLLM": {
    "name": "cwe-295wLLM",
    "type": "cwe-query",
    "cwe_id": "295",
    "cwe_id_short": "295",
    "cwe_id_tag": "CWE-295",
    "desc": "Improper Certificate Validation",
    "queries": [
      "cwe-queries/java/cwe-295/InsecureTrustManager.ql",
      "cwe-queries/java/cwe-295/MyInsecureTrustManager.qll",
      "cwe-queries/java/cwe-295/MyInsecureTrustManagerQuery.qll",
    ],
    "prompts": {
      "cwe_id": "CWE-295",
      "desc": "Improper Certificate Validation",
      "long_desc": """\
      When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client. The product might connect to a malicious host while believing it is a trusted host, or the product might be deceived into accepting spoofed data that appears to originate from a trusted host.""",
      "examples": [ 
        {
          "package": "org.keycloak.authentication.AuthenticationFlowContext",
          "class": "ValidateX509CertificateUsername",
          "method": "authenticate",
          "signature": "void authenticate(AuthenticationFlowContext context)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "com.tigervnc.rfb",
          "class": "CSecurityTLS",
          "method": "checkServerTrusted",
          "signature": "checkServerTrusted(X509Certificate[] chain, String authType)",
          "sink_args": ["chain", "authType"],
          "type": "sink"
        }, 
      ]
    }
  },

  "fetch_external_apis": {
    "name": "fetch_external_apis",
    "queries": [
      "queries/java/fetch_external_apis.ql"
    ]
  },
  "fetch_external_apis_python": {
    "name": "fetch_external_apis_python",
    "queries": [
      "queries/python/fetch_external_apis.ql"
    ]
  },
  "fetch_external_apis_cpp": {
    "name": "fetch_external_apis_cpp",
    "queries": [
      "queries/cpp/fetch_external_apis.ql"
    ]
  },
  "fetch_func_params": {
    "name": "fetch_func_params",
    "queries": [
      "queries/java/fetch_func_params.ql"
    ]
  },
  "fetch_func_params_python": {
    "name": "fetch_func_params_python",
    "queries": [
      "queries/python/fetch_func_params.ql"
    ]
  },
  "fetch_func_params_cpp": {
    "name": "fetch_func_params_cpp",
    "queries": [
      "queries/cpp/fetch_func_params.ql"
    ]
  },
  "fetch_func_locs": {
    "name": "fetch_func_locs",
    "queries": [
      "queries/java/fetch_func_locs.ql"
    ]
  },
  "fetch_func_locs_python": {
    "name": "fetch_func_locs_python",
    "queries": [
      "queries/python/fetch_func_locs.ql"
    ]
  },
  "fetch_func_locs_cpp": {
    "name": "fetch_func_locs_cpp",
    "queries": [
      "queries/cpp/fetch_func_locs.ql"
    ]
  },
  "fetch_class_locs": {
    "name": "fetch_class_locs",
    "queries": [
      "queries/java/fetch_class_locs.ql"
    ]
  },
  "fetch_sources": {
    "name": "fetch_sources",
    "queries": [
      "queries/java/fetch_sources.ql"
    ]
  },
  "fetch_sinks": {
    "name": "fetch_sinks",
    "queries": [
      "queries/java/fetch_sinks.ql"
    ]
  }
}
