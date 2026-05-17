# Python / C/C++ 原生 CodeQL 结果的 LLM 后审说明

本文说明当前新增的 native posthoc filtering：它针对 Python 和 C/C++ 的 CodeQL 原生查询结果进行 LLM 二次判断，整体风格参考 IRIS 原 Java posthoc 逻辑。

## 设计思路

当前路线不重新实现 LLM source/sink 打标签，而是在 CodeQL 原生查询已经产出 SARIF 后，对每条 CodeQL dataflow path 做后审。

它继承了 Java 线的几个核心做法：

- source 和 sink 提取所在代码上下文。
- 中间 steps 不展开完整代码，只给出 `- Step i [file:function]: line` 摘要。
- prompt 要求 LLM 输出固定 JSON。
- 同一组 source/sink 会复用缓存，避免重复调用 LLM。
- 输出过滤后的 SARIF，只保留 LLM 判定为 `is_vulnerable=true` 的路径。

## 相关代码

- `src/prompts.py`
  - 新增 `POSTHOC_FILTER_NATIVE_SYSTEM_PROMPT`
  - 新增 `POSTHOC_FILTER_NATIVE_USER_PROMPT`
  - 新增 `POSTHOC_FILTER_LANGUAGE_HINTS`

- `src/modules/native_contextual_analysis_pipeline.py`
  - 解析 CodeQL SARIF 的 `codeFlows`
  - 提取 Python / C/C++ source、sink 上下文
  - Python 使用 `ast` 提取函数范围
  - C/C++ 优先使用 tree-sitter 提取函数 / lambda 范围，失败时回退到启发式正则
  - 生成 IRIS 风格 prompt
  - 调用现有 LLM 接口
  - 输出 `results.json`、`results.sarif`、`results.csv`、`stats.json` 和 prompt 日志

- `src/codeql_vul.py`
  - 新增 `--llm-posthoc-filter`
  - 新增 `--posthoc-filter-only`
  - 新增 `--llm`
  - 新增 `--posthoc-batch-size`
  - 新增 `--posthoc-test-run`

## 使用方式

如果需要 C/C++ 更精确的函数范围切片，请确保环境里安装了 tree-sitter 依赖。当前 `environment.yml` 已加入：

```text
tree-sitter
tree-sitter-c
tree-sitter-cpp
```

如果是已有环境，可以手动安装：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
pip install tree-sitter tree-sitter-c tree-sitter-cpp
```

先确保已经有 CodeQL 原生结果：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --overwrite \
  <project_slug>
```

然后对已有 SARIF 单独做 LLM 后审：

先确认仓库根目录存在 `cloud_config.json`：

```json
{
  "key": "你的 API Key",
  "url": "https://api.deepseek.com",
  "model": "deepseek-v4-pro"
}
```

然后执行：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --posthoc-filter-only \
  --llm cloud \
  --overwrite \
  <project_slug>
```

也可以在运行 CodeQL 查询后立刻做 LLM 后审：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language cpp \
  --llm-posthoc-filter \
  --llm cloud \
  --overwrite \
  <project_slug>
```

如果只想看生成的 prompt，不调用 LLM：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --posthoc-filter-only \
  --posthoc-test-run \
  --overwrite \
  <project_slug>
```

## 产物位置

Python：

```text
output/<project>/codeql-python/<query>/posthoc-filter/
```

C/C++：

```text
output/<project>/codeql-cpp/<query>/posthoc-filter/
```

目录内主要文件：

- `results.json`：每条 code flow 的 prompt、LLM JSON 判断、是否使用缓存。
- `results.sarif`：过滤后的 SARIF，只保留 LLM 判定为漏洞的路径。
- `results.csv`：便于人工快速查看的结果摘要。
- `stats.json`：调用次数、缓存次数、失败数、保留路径数。
- `logs/raw_user_prompt_*`：实际发送给 LLM 的 user prompt。
- `logs/raw_llm_response_*`：LLM 原始响应。

## 当前 smoke 验证

Python smoke：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --posthoc-filter-only \
  --llm cloud \
  --overwrite \
  iris-python-smoke
```

结果：

```text
output/iris-python-smoke/codeql-python/cwe-078wCodeQL/posthoc-filter/results.csv
```

LLM 判定：

```text
is_vulnerable = true
source = request.args["cmd"]
sink = os.system(command)
```

C/C++ smoke：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language cpp \
  --posthoc-filter-only \
  --llm cloud \
  --overwrite \
  iris-cpp-smoke
```

结果：

```text
output/iris-cpp-smoke/codeql-cpp/cwe-078wCodeQL/posthoc-filter/results.csv
```

LLM 判定：

```text
is_vulnerable = true
source = argv[1]
sink = system(command)
```

## 注意事项

- 当前 posthoc 只处理 SARIF 中带 `codeFlows` 的 path-problem 结果（IRIS的逻辑）。
- Python 路径会跳过开头的 `import/from import` 符号位置，避免把导入语句误当成攻击者 source。
- Python 函数范围使用 `ast` 提取。
- C/C++ 函数范围优先使用 tree-sitter 提取，能够比正则更好地处理多行函数签名、类成员函数、lambda、模板等语法；如果 tree-sitter 不可用，会回退到轻量启发式匹配。
- 中间 steps 会保留 SARIF message，例如 `(*access to array)`、`(sprintf output argument)`，这样同一源码行上的不同数据流节点也能区分。
- 远程模型统一通过 `--llm cloud` 进入云端适配器；真实请求使用仓库根目录 `cloud_config.json` 的 `model` 字段。
- 当前实现没有破坏 Java 原 posthoc；Java 仍走原 `ContextualAnalysisPipeline`。
- Python / C/C++ 的 LLM 打标签路线已经复用了这套 native posthoc；目前 `cwe-022wLLM`、`cwe-078wLLM`、`cwe-079wLLM`、`cwe-089wLLM`、`cwe-094wLLM`、`cwe-352wLLM`、`cwe-502wLLM`、`cwe-611wLLM`、`cwe-918wLLM` 均可产出对应的 posthoc 结果。
