# IRIS 接入 DeepSeek 远程 API 说明

这份文档说明两件事：

1. 为什么要给 IRIS 增加 DeepSeek 远程 API 支持
2. 如何使用 DeepSeek 远程 API 跑通 README 里的示例项目

## 一、为什么要这样做

IRIS 原始 README 里的示例命令是：

```bash
python src/iris.py --query cwe-022wLLM --run-id test --llm qwen2.5-coder-7b perwendel__spark_CVE-2018-9159_2.7.1
```

这条命令默认走的是本地模型加载，也就是需要在本机下载并运行一个 7B 量级的大模型。

在我们这次的环境里，这条路线不太合适，主要原因有：

- 当前 `iris` 环境里的 PyTorch 是 CPU 版
- WSL 里当时没有可直接使用的 CUDA 环境
- 本地运行 7B 模型不仅需要磁盘，还需要明显更多的运行内存 / 显存

而 IRIS 自身已经有模型抽象层，也已经支持一些“远程模型后端”的思路，比如 GPT、Gemini 这类接口。因此，最稳妥、改动最小的办法，就是：

- 保留原有本地模型逻辑
- 额外新增一条 DeepSeek 远程 API 路线

这样既能尽快把 IRIS 原有 Java 流程跑通，也不会破坏原始代码的整体结构。

## 二、改了什么

主要改动在：

- `src/models/deepseek.py`

这个文件现在同时支持两类模型名称。

### 1. 本地模型

下面这些名称仍然保留原来的本地 Hugging Face 加载逻辑：

- `deepseekcoder-33b`
- `deepseekcoder-7b`
- `deepseekcoder-v2-15b`

这部分仍然会走 `from_pretrained(...)`，也就是本地模型加载。

### 2. 远程 API 模型

新增了这两个名称：

- `deepseek-chat`
- `deepseek-reasoner`

当 `--llm` 使用这两个名称时，IRIS 不再尝试从本地加载模型，而是改为调用 DeepSeek 的远程 API。

## 三、具体是怎么做的

在 `src/models/deepseek.py` 里，远程 API 分支的核心逻辑是：

1. 先判断当前模型名是不是远程模型
2. 从环境变量里读取 `DEEPSEEK_API_KEY`
3. 从环境变量里读取 `DEEPSEEK_API_BASE`
4. 如果没有设置 `DEEPSEEK_API_BASE`，默认使用：

```text
https://api.deepseek.com
```

5. 创建 OpenAI 兼容客户端：

```python
OpenAI(api_key=api_key, base_url=base_url)
```

6. 复用 IRIS 现有的 prompt 结构，把 `system` 和 `user` 消息发给：

```python
client.chat.completions.create(...)
```

也就是说，这次改动只是在“模型调用层”加了一条远程路径，IRIS 的主流程本身没有被推翻。

## 四、为什么这种做法更合适

这条方案的优点是：

- 不影响原来的 `deepseekcoder-*` 本地模型逻辑
- 不需要重写 IRIS 的 prompt 生成和调用流程
- 不需要在本机下载和运行大模型
- 和 IRIS 现有的模型抽象方式保持一致

简单说，就是：

- 改动小
- 风险低
- 能快速把现有 Java 基线流程跑通

## 五、密钥怎么管理

为了避免把 API key 写死在源码里，这次新增了一个本地配置文件：

- `.env.deepseek.local`

并且已经把它加入了：

- `.gitignore`

这样可以避免 key 被误提交进仓库。

这个文件的典型内容是：

```bash
export DEEPSEEK_API_KEY="你的 DeepSeek API Key"
```

如果你需要自定义 API 地址，也可以再加一行：

```bash
export DEEPSEEK_API_BASE="https://api.deepseek.com"
```

使用时只需要在仓库根目录执行：

```bash
source .env.deepseek.local
```

## 六、示例项目说明

这次用于验证的示例项目是：

- `perwendel__spark_CVE-2018-9159_2.7.1`

这也是主 `README.md` 里使用的示例项目。

## 七、从头执行示例项目

下面是从头到尾的一套命令说明。

### 第 1 步：抓取并构建项目

```bash
HOME=/home/lifew/iris /home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/fetch_and_build.py --filter perwendel__spark_CVE-2018-9159_2.7.1 --verbose
```

这一步会：

- 拉取项目源码
- 切换到数据集对应的漏洞版本
- 按 IRIS 记录的依赖版本构建项目

### 第 2 步：构建 CodeQL 数据库

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py --project perwendel__spark_CVE-2018-9159_2.7.1
```

这一步会为该 Java 项目生成后续分析所需的 CodeQL 数据库。

### 第 3 步：加载 DeepSeek API Key

```bash
source /home/lifew/iris/.env.deepseek.local
```

### 第 4 步：运行 IRIS 分析

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/iris.py \
  --query cwe-022wLLM \
  --run-id test-deepseek \
  --llm deepseek-chat \
  perwendel__spark_CVE-2018-9159_2.7.1
```

这里最关键的变化是：

- 原 README 用的是本地 `qwen2.5-coder-7b`
- 这里改成了远程 `deepseek-chat`

## 八、运行后会生成什么

这次运行的输出目录在：

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/`

下面是最值得关注的几类产物。

### 1. 总日志

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/log/`

这里保存了这次运行的整体日志，可以看到每个阶段在做什么。

### 2. 原始 CodeQL 查询结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM/results.csv`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM/results.sarif`

这是 IRIS 生成建模规则后，最终交给 CodeQL 跑出来的原始漏洞结果。

### 3. LLM 标注结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/analysis/cwe-022wLLM/llm_labelled_source_apis.json`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/analysis/cwe-022wLLM/llm_labelled_sink_apis.json`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/analysis/cwe-022wLLM/llm_labelled_taint_prop_apis.json`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/analysis/cwe-022wLLM/llm_labelled_source_func_params.json`

这些文件是 IRIS 在“让 LLM 识别 source / sink / taint propagator”之后得到的关键中间产物。

### 4. 自动生成的项目专属 CodeQL 查询

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/myqueries/cwe-022wLLM/`

这里面最重要的文件包括：

- `MySources.qll`
- `MySinks.qll`
- `MySummaries.qll`
- `specs.model.yml`
- `cwe-022wLLM.ql`

这一层可以理解成：

- IRIS 把 LLM 的判断结果
- 转成了真正可执行的 CodeQL 建模和查询规则

### 5. Posthoc filtering 结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM-posthoc-filter/results.json`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM-posthoc-filter/results.sarif`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM-posthoc-filter/stats.json`

这一层是 IRIS 在拿到原始路径后，再次调用 LLM 做“路径级别误报过滤”后的结果。

### 6. 最终汇总结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM-final/results.json`

如果你只想快速看这次运行的大盘统计，这个文件最值得先看。

## 九、这次成功运行的结果摘要

这次 `test-deepseek` 成功运行后的最终统计包括：

- `num_external_api_calls = 5265`
- `num_api_candidates = 553`
- `num_labelled_sources = 44`
- `num_labelled_taint_propagators = 77`
- `num_labelled_sinks = 35`
- `num_labelled_func_param_sources = 42`

Vanilla 结果：

- `num_results = 16`
- `num_paths = 56`

Posthoc filtering 后：

- `num_results = 16`
- `num_paths = 6`

## 十、补充说明

- 这次增加的 DeepSeek 远程 API 支持，本质上是一个“运行方式替代方案”
- 它没有改变 IRIS 原有的 Java 分析主流程
- 后续如果需要，也可以按类似思路继续接入其他 OpenAI 兼容接口

如果你后面还要继续做 Python、C/C++ 扩展，这个改动也很有价值，因为它把“LLM 后端”和“本地大模型部署条件”解耦开了。
