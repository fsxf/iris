# Python / C/C++ LLM 打标签路线说明

本文说明当前已经接入的 **Python / C/C++ + IRIS 风格 LLM 打标签路线**。这条路线不是 CodeQL 官方原生查询路线，而是尽量复用原 IRIS Java 的核心流程：

```text
采集 API / 函数参数
-> LLM 打 source / sink / taint-propagator 标签
-> 生成项目专属 MySources.qll / MySinks.qll / MySummaries.qll
-> 跑自定义 CodeQL taint tracking
-> native posthoc 过滤误报
```

当前接入状态：

```text
已完整 smoke 验证:
Python: language=python, query=cwe-078wLLM, project=iris-python-smoke
C/C++ : language=cpp,    query=cwe-078wLLM, project=iris-cpp-smoke

已完整 cloud + posthoc 验证:
Python: cwe-022wLLM, cwe-079wLLM, cwe-089wLLM, cwe-094wLLM, cwe-502wLLM, cwe-918wLLM
C/C++ : cwe-022wLLM, cwe-079wLLM, cwe-089wLLM, cwe-094wLLM, cwe-502wLLM, cwe-918wLLM
```

说明：

```text
CWE-078 已经跑过端到端 LLM 打标签、动态 QLL 生成、CodeQL 查询、posthoc 过滤。
CWE-022 / 079 / 089 / 094 / 502 / 918 已经在 Python 与 C/C++ smoke 项目上跑过完整 cloud LLM 打标签、动态 QLL 生成、CodeQL 查询、posthoc 过滤，并确认有真实告警和 raw prompt/response 日志。
```

## 当前能力

Python 和 C/C++ 目前都已经实现：

- Stage 1：收集项目源码中的调用点，作为外部 API 候选。
- Stage 2：收集项目内部函数参数，作为 source 参数候选。
- Stage 3：调用 `--llm cloud` 标注 API 的 `source`、`sink`、`taint-propagator`。
- Stage 4：调用 `--llm cloud` 标注内部函数参数 source。
- Stage 5：生成对应语言的 `MySources.qll`、`MySinks.qll`、`MySummaries.qll`。
- Stage 6：运行对应语言的 CWE-specific 自定义 CodeQL path-problem 查询。
- Stage 7：非 Java 路线使用 SARIF passthrough 后处理。
- Stage 8：接入 native posthoc，对 SARIF `codeFlows` 做 LLM 二次判断。
- Stage 9：非 Java 暂时跳过原 IRIS evaluation。

## 相关文件

### 语言采集 query

```text
src/queries/python/fetch_external_apis.ql
src/queries/python/fetch_func_params.ql
src/queries/python/fetch_func_locs.ql

src/queries/cpp/fetch_external_apis.ql
src/queries/cpp/fetch_func_params.ql
src/queries/cpp/fetch_func_locs.ql
```

说明：

- `fetch_external_apis.ql`：收集项目调用点，沿用 IRIS “先收集候选，再交给 LLM 判断”的思路。
- `fetch_func_params.ql`：收集内部函数参数，用于 Stage 4 参数 source 标注。
- `fetch_func_locs.ql`：收集函数位置，为 native posthoc 和后续上下文提取准备。
- C/C++ 采集 query 已排除 `.miniconda3`、`sysroot`、`/usr/include` 等系统头文件路径，避免把 libc 头文件声明送给 LLM。

### CWE 查询模板

```text
src/cwe-queries/python/cwe-078/cwe-078wLLM.ql
src/cwe-queries/python/cwe-078/MyCommandInjectionQuery.qll
src/cwe-queries/python/cwe-022/cwe-022wLLM.ql
src/cwe-queries/python/cwe-022/MyTaintedPathQuery.qll
src/cwe-queries/python/cwe-079/cwe-079wLLM.ql
src/cwe-queries/python/cwe-079/MyXssQuery.qll
src/cwe-queries/python/cwe-089/cwe-089wLLM.ql
src/cwe-queries/python/cwe-089/MySqlInjectionQuery.qll
src/cwe-queries/python/cwe-094/cwe-094wLLM.ql
src/cwe-queries/python/cwe-094/MyCodeInjectionQuery.qll
src/cwe-queries/python/cwe-502/cwe-502wLLM.ql
src/cwe-queries/python/cwe-502/MyUnsafeDeserializationQuery.qll
src/cwe-queries/python/cwe-918/cwe-918wLLM.ql
src/cwe-queries/python/cwe-918/MyRequestForgeryQuery.qll

src/cwe-queries/cpp/cwe-078/cwe-078wLLM.ql
src/cwe-queries/cpp/cwe-078/MyCommandInjectionQuery.qll
src/cwe-queries/cpp/cwe-022/cwe-022wLLM.ql
src/cwe-queries/cpp/cwe-022/MyTaintedPathQuery.qll
src/cwe-queries/cpp/cwe-079/cwe-079wLLM.ql
src/cwe-queries/cpp/cwe-079/MyXssQuery.qll
src/cwe-queries/cpp/cwe-089/cwe-089wLLM.ql
src/cwe-queries/cpp/cwe-089/MySqlInjectionQuery.qll
src/cwe-queries/cpp/cwe-094/cwe-094wLLM.ql
src/cwe-queries/cpp/cwe-094/MyCodeInjectionQuery.qll
src/cwe-queries/cpp/cwe-502/cwe-502wLLM.ql
src/cwe-queries/cpp/cwe-502/MyUnsafeDeserializationQuery.qll
src/cwe-queries/cpp/cwe-918/cwe-918wLLM.ql
src/cwe-queries/cpp/cwe-918/MyRequestForgeryQuery.qll
```

说明：

- `cwe-xxxwLLM.ql` 是最终 `@kind path-problem` 查询入口。
- `My...Query.qll` 定义对应语言、对应 CWE 的 taint tracking 配置。
- 它们会 import 运行时生成的 `MySources`、`MySinks`、`MySummaries`。
- 新增 CWE 模板参考了 Java 原路线的 CWE-specific 文件结构，但第一版仍主要依赖 LLM 标注的 source / sink / taint-propagator 与通用 taint flow。像 CWE-094 这类 Java 中带 SpEL / Template Injection 结构约束的规则，后续可以继续补更强的语言特定结构判断。

### 动态 QLL renderer

```text
src/codeql_queries_python.py
src/codeql_queries_cpp.py
```

说明：

- Python renderer 负责生成 Python 版 `MySources.qll`、`MySinks.qll`、`MySummaries.qll`。
- C/C++ renderer 负责生成 C/C++ 版 `MySources.qll`、`MySinks.qll`、`MySummaries.qll`。
- C/C++ 的 `MySummaries.qll` 额外处理 `sprintf`、`snprintf`、`strcpy`、`strcat` 等输出 buffer 风格函数。
- 对 `sprintf` 这类 C varargs 函数，C/C++ renderer 会额外生成若干个参数位到输出 buffer 的 summary 边，避免 CodeQL 元数据只暴露固定参数而漏掉真实输入。

### Prompt 配置

```text
src/prompts.py
src/language_prompts.py
src/queries.py
```

分工：

- `src/prompts.py`：IRIS 原本的阶段级 prompt 模板，例如 API 打标签、函数参数打标签、posthoc。
- `src/language_prompts.py`：语言级 prompt 覆盖或补充，例如 Python/C++ 如何描述函数、参数和模块。
- `src/queries.py`：CWE 级配置，例如 `cwe-078wLLM.prompts.long_desc`，以及 `languages.python/cpp.prompts.api_examples` 和 `function_param_hint`。

当前 Stage 3 API 打标签时，Python/C++ 和 Java 一样都会使用顶层：

```text
QUERIES["<query>"]["prompts"]["desc"]
QUERIES["<query>"]["prompts"]["long_desc"]
```

语言差异主要放在：

```text
QUERIES["<query>"]["languages"]["python"]["prompts"]["api_examples"]
QUERIES["<query>"]["languages"]["cpp"]["prompts"]["api_examples"]
```

Stage 4 函数参数 source 标注则使用对应语言的 `function_param_hint`。

## 运行方式

前提：仓库根目录存在 `cloud_config.json`，例如：

```json
{
  "key": "你的 API Key",
  "url": "https://api.deepseek.com",
  "model": "deepseek-v4-pro"
}
```

如果已经激活 conda 环境：

```bash
conda activate iris
export PATH=/home/lifew/iris/codeql:$PATH
```

可以使用简化命令。

下面示例以 `cwe-078wLLM` 为例。如果要尝试已经接入的其他 CWE，可以把 `--query` 替换为：

```text
cwe-022wLLM
cwe-079wLLM
cwe-089wLLM
cwe-094wLLM
cwe-502wLLM
cwe-918wLLM
```

Python：

```bash
python src/iris.py \
  --query cwe-078wLLM \
  --language python \
  --run-id llm-python-smoke \
  --llm cloud \
  --num-threads 1 \
  iris-python-smoke
```

C/C++：

```bash
python src/iris.py \
  --query cwe-078wLLM \
  --language cpp \
  --run-id llm-cpp-smoke \
  --llm cloud \
  --num-threads 1 \
  iris-cpp-smoke
```

如果没有激活 conda，可以使用完整命令。

Python：

```bash
HOME=/home/lifew/iris PYTHONPATH=/home/lifew/iris:/home/lifew/iris/src PATH=/home/lifew/iris/codeql:$PATH \
/home/lifew/iris/.miniconda3/bin/conda run -n iris python src/iris.py \
  --query cwe-078wLLM \
  --language python \
  --run-id llm-python-smoke \
  --llm cloud \
  --overwrite-api-candidates \
  --overwrite-func-param-candidates \
  --overwrite-labelled-apis \
  --overwrite-llm-cache \
  --overwrite-labelled-func-param \
  --overwrite-cwe-query-result \
  --overwrite-postprocess-cwe-query-result \
  --overwrite-posthoc-filter \
  --skip-evaluation \
  --num-threads 1 \
  iris-python-smoke
```

C/C++：

```bash
HOME=/home/lifew/iris PYTHONPATH=/home/lifew/iris:/home/lifew/iris/src PATH=/home/lifew/iris/codeql:$PATH \
/home/lifew/iris/.miniconda3/bin/conda run -n iris python src/iris.py \
  --query cwe-078wLLM \
  --language cpp \
  --run-id llm-cpp-smoke \
  --llm cloud \
  --overwrite-api-candidates \
  --overwrite-func-param-candidates \
  --overwrite-labelled-apis \
  --overwrite-llm-cache \
  --overwrite-labelled-func-param \
  --overwrite-cwe-query-result \
  --overwrite-postprocess-cwe-query-result \
  --overwrite-posthoc-filter \
  --skip-evaluation \
  --num-threads 1 \
  iris-cpp-smoke
```

## 关键产物

以 `<project>` 和 `<run-id>` 表示项目名和运行 ID。

### Stage 1 / 2 采集结果

```text
output/<project>/<run-id>/fetch_external_apis/results.csv
output/<project>/<run-id>/fetch_func_params/results.csv
output/<project>/<run-id>/analysis/common/candidate_apis.csv
output/<project>/<run-id>/analysis/common/source_func_param_candidates.csv
```

### Stage 3 / 4 LLM 标签

```text
output/<project>/<run-id>/analysis/<query>/llm_labelled_source_apis.json
output/<project>/<run-id>/analysis/<query>/llm_labelled_sink_apis.json
output/<project>/<run-id>/analysis/<query>/llm_labelled_taint_prop_apis.json
output/<project>/<run-id>/analysis/<query>/llm_labelled_source_func_params.json
```

### Stage 5 动态生成的 QLL

```text
output/<project>/<run-id>/myqueries/<query>/MySources.qll
output/<project>/<run-id>/myqueries/<query>/MySinks.qll
output/<project>/<run-id>/myqueries/<query>/MySummaries.qll
```

### Stage 6 CodeQL 结果

```text
output/<project>/<run-id>/<query>/results.csv
output/<project>/<run-id>/<query>/results.sarif
output/<project>/<run-id>/<query>/results_pp.sarif
```

### Stage 8 posthoc 结果

```text
output/<project>/<run-id>/<query>-posthoc-filter/results.csv
output/<project>/<run-id>/<query>-posthoc-filter/results.json
output/<project>/<run-id>/<query>-posthoc-filter/results.sarif
output/<project>/<run-id>/<query>-posthoc-filter/stats.json
```

## Smoke 验证结果

Python smoke：

```text
project = iris-python-smoke
run-id  = llm-python-smoke
```

CodeQL 动态查询可输出 2 条路径：

```text
run_command(command) -> os.system(command)
input() -> os.system(command)
```

posthoc 判断其中 1 条为 true vulnerability：

```text
input() -> os.system(command)
```

C/C++ smoke：

```text
project = iris-cpp-smoke
run-id  = llm-cpp-smoke-v2
```

LLM 标注结果：

```text
source function parameter: main argv
taint propagator: sprintf
sink: system p0
```

CodeQL 输出 1 条真实告警：

```text
main.c:4 argv
-> main.c:7 sprintf output argument
-> main.c:8 system(command)
```

posthoc 判断：

```text
is_vulnerable = true
source_is_false_positive = false
sink_is_false_positive = false
```

新增多 CWE smoke 验证：

```text
Python project = iris-python-multi-cwe-smoke
C/C++  project = iris-cpp-multi-cwe-smoke
LLM backend    = --llm cloud
```

完整验证矩阵：

| 语言 | CWE | run-id | CodeQL CSV 行数 | posthoc CSV 行数 | posthoc raw 日志数 |
|---|---:|---|---:|---:|---:|
| Python | 022 | `llm-python-cwe022-cloud-full` | 2 | 3 | 6 |
| Python | 079 | `llm-python-cwe079-cloud-full` | 3 | 4 | 6 |
| Python | 089 | `llm-python-cwe089-cloud-full` | 4 | 5 | 10 |
| Python | 094 | `llm-python-cwe094-cloud-full` | 2 | 3 | 6 |
| Python | 502 | `llm-python-cwe502-cloud-full` | 3 | 4 | 6 |
| Python | 918 | `llm-python-cwe918-cloud-full` | 2 | 3 | 6 |
| C/C++ | 022 | `llm-cpp-cwe022-cloud-full` | 4 | 5 | 10 |
| C/C++ | 079 | `llm-cpp-cwe079-cloud-full` | 3 | 4 | 6 |
| C/C++ | 089 | `llm-cpp-cwe089-cloud-full` | 1 | 2 | 4 |
| C/C++ | 094 | `llm-cpp-cwe094-cloud-full` | 2 | 3 | 6 |
| C/C++ | 502 | `llm-cpp-cwe502-cloud-full` | 3 | 4 | 6 |
| C/C++ | 918 | `llm-cpp-cwe918-cloud-full` | 2 | 3 | 6 |
 
这些 run 均已确认存在：

```text
<query>/results.csv
<query>/results.sarif
<query>/results_pp.sarif
<query>-posthoc-filter/results.csv
<query>-posthoc-filter/results.json
<query>-posthoc-filter/results.sarif
<query>-posthoc-filter/stats.json
<query>-posthoc-filter/logs/raw_user_prompt_*.txt
<query>-posthoc-filter/logs/raw_llm_response_*.txt
```

注意：如果之前某次 LLM API 标注空返回或标签明显错误，重新跑时建议加 `--overwrite-llm-cache`。否则 IRIS 会复用旧的 API 标签缓存，可能出现 `#To Query APIs: 0, #Cached: ...`，导致问题被旧缓存保留下来。

## 当前边界

- 当前 Python / C/C++ 已完整端到端验证 CWE-078。
- 当前 Python / C/C++ 已完整端到端验证 CWE-022、CWE-079、CWE-089、CWE-094、CWE-502、CWE-918。
- Python `MySummaries.qll` 当前采用保守的 IRIS 风格：默认参数流向返回值，可能扩大召回，后续依赖 posthoc 降噪。
- C/C++ `MySummaries.qll` 当前覆盖常见返回值传播和输出 buffer 传播，后续其他 CWE 可能需要补充更多 API 传播形态。
- C/C++ 项目构建仍依赖 CodeQL DB 是否正确构建；有编译需求的项目需要提供 build command 或可用的 `make/cmake/gcc/g++` 环境。
- 非 Java 仍跳过原 IRIS evaluation，因此最终评估指标不会像 CVE-Bench Java 那样自动生成。

## 后续扩展建议

如果继续扩展 Python 或 C/C++ 的其他 CWE：

- 在 `src/cwe-queries/<language>/cwe-xxx/` 新增对应 CWE 模板。
- 在 `src/queries.py` 的 query 配置里增加 `languages.<language>.queries`。
- 在 `languages.<language>.prompts` 中补 CWE-specific `api_examples` 和 `function_param_hint`。
- 如果该 CWE 需要新的传播形态，再扩展对应的 `src/codeql_queries_<language>.py`。
