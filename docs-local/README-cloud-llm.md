# IRIS 云端 LLM 配置说明

本文说明如何让 IRIS 通过 `cloud_config.json` 调用任意 OpenAI-compatible 远程模型。这里的 `cloud` 是通用云端入口，不绑定 DeepSeek；DeepSeek 只是当前示例 provider。

## 一、为什么使用 cloud

IRIS 原始 README 示例使用本地模型：

```bash
python src/iris.py --query cwe-022wLLM --run-id test --llm qwen2.5-coder-7b perwendel__spark_CVE-2018-9159_2.7.1
```

本地模型需要下载权重，并在运行时占用较多内存或显存。当前项目更适合把模型能力放到远程服务上：

- 不需要本地部署 7B 或更大的模型。
- 前端或后端只需要传入 `key`、`url`、`model`。
- 后续切换模型时只改配置，不改 IRIS 分析流程。
- Python 和 C/C++ 的 LLM 打标签、posthoc 都可以复用同一个入口。

## 二、代码入口

云端模型入口位于：

```text
src/models/cloud.py
```

模型工厂中：

```text
--llm cloud -> CloudModel -> cloud_config.json -> OpenAI-compatible API
```

本地 DeepSeek Coder 模型仍然走：

```text
--llm deepseekcoder-7b -> src/models/deepseek.py
```

注意：不再使用 `--llm deepseek-chat` 作为兼容别名。远程模型统一写 `--llm cloud`，真实模型名只放在 `cloud_config.json`。

## 三、配置文件

在仓库根目录创建：

```text
cloud_config.json
```

内容示例：

```json
{
  "key": "你的 API Key",
  "url": "https://api.deepseek.com",
  "model": "deepseek-v4-pro"
}
```

字段含义：

- `key`：远程服务 API key。
- `url`：OpenAI-compatible API base URL。
- `model`：真正发送给远程服务的模型名。
- `retries`：可选，cloud 返回空内容或请求失败时的最大重试次数，默认 `3`。

只要服务兼容 OpenAI Chat Completions 接口，就可以换成其他 provider 或自建服务：

```python
client.chat.completions.create(...)
```

真实 `cloud_config.json` 已加入 `.gitignore`，不要提交。仓库中只提交：

```text
cloud_config.example.json
```

## 四、简化运行命令

如果已经激活 conda 环境，并且 CodeQL 已加入 `PATH`：

```bash
conda activate iris
export PATH=/home/lifew/iris/codeql:$PATH
```

Java README 示例可以这样跑：

```bash
python src/iris.py \
  --query cwe-022wLLM \
  --run-id test-cloud \
  --llm cloud \
  perwendel__spark_CVE-2018-9159_2.7.1
```

Python CWE-078 LLM 打标签路线可以这样跑：

```bash
python src/iris.py \
  --query cwe-078wLLM \
  --language python \
  --run-id llm-python-smoke \
  --llm cloud \
  iris-python-smoke
```

如果没有激活 conda，建议用完整命令前缀：

```bash
HOME=/home/lifew/iris PATH=/home/lifew/iris/codeql:$PATH \
/home/lifew/iris/.miniconda3/bin/conda run -n iris python src/iris.py \
  --query cwe-078wLLM \
  --language python \
  --run-id llm-python-smoke \
  --llm cloud \
  iris-python-smoke
```

## 五、产物怎么看

LLM 打标签路线的关键产物仍然和 IRIS 原流程一致：

```text
output/<project>/<run-id>/analysis/<query>/llm_labelled_source_apis.json
output/<project>/<run-id>/analysis/<query>/llm_labelled_sink_apis.json
output/<project>/<run-id>/analysis/<query>/llm_labelled_taint_prop_apis.json
output/<project>/<run-id>/myqueries/<query>/MySources.qll
output/<project>/<run-id>/myqueries/<query>/MySinks.qll
output/<project>/<run-id>/myqueries/<query>/MySummaries.qll
output/<project>/<run-id>/<query>/results.csv
output/<project>/<run-id>/<query>/results.sarif
```

posthoc 结果通常在：

```text
output/<project>/<run-id>/<query>-posthoc-filter/
```

## 六、注意事项

- `--llm cloud` 只决定走云端适配器，不决定具体模型。
- 具体模型由 `cloud_config.json` 的 `model` 字段决定。
- 如果要换模型或 provider，只改 `cloud_config.json`。
- 如果 provider 不兼容 OpenAI Chat Completions 接口，需要额外写新的模型适配器。
- cloud 适配器会对“空响应”或请求异常自动重试，并在 IRIS run 日志里记录 `Cloud API empty response on attempt ...` 或 `Cloud API request failed ...`。
- 如果某次空响应已经污染了 API 标签缓存，重新跑时加 `--overwrite-llm-cache`，否则 IRIS 可能继续复用旧的 `type=none` 标签。
