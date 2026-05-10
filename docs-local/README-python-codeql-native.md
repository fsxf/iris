# Python 项目走 CodeQL 原生查询路线说明

这份文档说明当前 IRIS 已经新增的 **Python 原生 CodeQL 查询路线**：

- 做了哪些改动
- 如何使用
- 输出产物在哪里
- 当前能力边界是什么
- 后续如何兼容 C/C++

这里的“原生 CodeQL 查询路线”指的是：

```text
Python 源码
-> CodeQL 数据库 db-python
-> CodeQL 官方 Python 查询
-> SARIF / CSV 结果
```

这一条路线不经过 IRIS 的 LLM source/sink/parameter 标注流程，也不会生成：

- `MySources.qll`
- `MySinks.qll`
- `MySummaries.qll`
- `specs.model.yml`

如果要看 Python / C/C++ 已经接入的 IRIS 风格 LLM 打标签路线，请看：

```text
docs-local/README-llm-routes.md
```

如果要看项目内自定义 CodeQL 查询路线，请看：

```text
docs-local/README-custom-codeql-queries.md
```

## 一、为什么先走原生 CodeQL 查询

IRIS 原来的主流程主要针对 Java，尤其是下面这些部分和 Java 强绑定：

- Java CodeQL 数据库目录：`db-java`
- Java 查询包：`codeql/java-queries`
- Java CodeQL 模板：`import java`
- Java API / parameter 候选提取查询
- Java 版 source/sink/summary QLL 生成逻辑

如果一开始就把 Python 也接入 LLM 标注路线，改动会很大。

因此第一版先走更稳的路线：

```text
先复用 CodeQL 官方 Python 安全查询
先打通 Python 建库、查询、SARIF/CSV 输出
再逐步补 LLM 标注和 posthoc filtering
```

## 二、这次做了哪些改动

### 1. 新增语言配置模块

新增文件：

- `src/language_config.py`

这个文件集中管理不同语言的 CodeQL 配置，例如：

```text
java   -> db-java   -> java-queries   -> Security/CWE/CWE-xxx
python -> db-python -> python-queries -> Security/CWE-xxx
cpp    -> db-cpp    -> cpp-queries    -> Security/CWE/CWE-xxx
```

这样后续扩展 C/C++ 时，不需要在各处硬编码路径。

### 2. 扩展 CodeQL 建库脚本

修改文件：

- `scripts/build_codeql_dbs.py`

新增参数：

```bash
--language java|python|cpp
```

默认仍然是 Java，不破坏原有 Java 流程。

现在可以为 Python 项目创建 CodeQL 数据库：

```bash
python scripts/build_codeql_dbs.py \
  --project <project-name> \
  --language python
```

生成的数据库目录中会包含：

```text
data/codeql-dbs/<project-name>/db-python
```

### 3. 扩展原生 CodeQL 查询入口

修改文件：

- `src/codeql_vul.py`

新增参数：

```bash
--language java|python|cpp
```

Python 路线会：

- 根据 `--language python` 自动选择 `python-queries`
- 根据 `--query cwe-xxxwCodeQL` 自动解析 CWE 编号
- 跑 CodeQL 官方 Python 查询目录
- 输出 SARIF 和 CSV
- 自动跳过 Java CWE-Bench 的 evaluation

### 4. 支持未注册的 `cwe-xxxwCodeQL`

原来 `codeql_vul.py` 依赖 `src/queries.py` 里手工注册的 query。

现在做了方式 B：

```text
如果 query 在 queries.py 里：
  必须是 type=codeql-query
  使用其中的 cwe_id

如果 query 不在 queries.py 里：
  只要名字匹配 cwe-数字wCodeQL 或 cwe-数字wCodeQLExp
  就自动解析 CWE 编号
  再根据 language 去找对应 CodeQL 查询目录
```

例如，即使 `src/queries.py` 里没有 `cwe-918wCodeQL`，也可以直接运行：

```bash
python src/codeql_vul.py \
  --query cwe-918wCodeQL \
  --language python \
  <project-name>
```

它会自动寻找：

```text
codeql/qlpacks/codeql/python-queries/<version>/Security/CWE-918/
```

### 5. 收紧原生路线和 LLM 路线的边界

`src/codeql_vul.py` 现在只负责原生 CodeQL 查询。

因此下面这种 LLM 查询名不会被它误当成原生查询执行：

```bash
python src/codeql_vul.py --query cwe-022wLLM ...
```

`cwe-xxxwLLM` 仍然属于 IRIS LLM 路线，应继续使用：

```bash
python src/iris.py --query cwe-022wLLM ...
```

这不会破坏原有 Java LLM 流程。

## 三、如何准备 Python 项目

把 Python 项目源码放到：

```text
data/project-sources/<project-name>/
```

例如：

```text
data/project-sources/my-python-app/
```

如果你已经有自己的源码目录，也可以在建库时通过 `--sources-path` 指定源码根目录。

## 四、如何运行

建议先进入 `iris` conda 环境，并确保 CodeQL 在 `PATH` 中：

```bash
conda activate iris
export PATH="$PWD/codeql:$PATH"
```

如果不想手动 activate，也可以使用 `conda run -n iris`。

### 第 1 步：创建 Python CodeQL 数据库

```bash
python scripts/build_codeql_dbs.py \
  --project <project-name> \
  --language python
```

示例：

```bash
python scripts/build_codeql_dbs.py \
  --project iris-python-smoke \
  --language python
```

成功后应出现：

```text
data/codeql-dbs/<project-name>/db-python
```

### 第 2 步：运行某个 CWE 的官方 Python 查询

命令格式：

```bash
python src/codeql_vul.py \
  --query cwe-<CWE编号>wCodeQL \
  --language python \
  <project-name>
```

示例：命令注入 CWE-078

```bash
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  <project-name>
```

示例：SSRF CWE-918

```bash
python src/codeql_vul.py \
  --query cwe-918wCodeQL \
  --language python \
  <project-name>
```

如果需要强制重跑：

```bash
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --overwrite \
  <project-name>
```

## 五、查询文件是如何定位的

以这个命令为例：

```bash
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  my-python-app
```

当前逻辑是：

```text
cwe-078wCodeQL
-> 解析出 CWE 编号 078
-> language=python
-> 选择 python-queries
-> 拼出 Security/CWE-078
-> 调用 codeql database analyze
```

最终查询目录类似：

```text
codeql/qlpacks/codeql/python-queries/1.6.6/Security/CWE-078/
```

如果换成 C/C++，后续会走：

```text
codeql/qlpacks/codeql/cpp-queries/<version>/Security/CWE/CWE-078/
```

这个差异由 `src/language_config.py` 统一处理。

## 六、输出产物在哪里

Python 原生 CodeQL 查询的输出目录是：

```text
output/<project-name>/codeql-python/<query-name>/
```

例如：

```text
output/iris-python-smoke/codeql-python/cwe-078wCodeQL/
```

里面主要有：

```text
results.sarif
results.csv
```

### `results.sarif`

SARIF 是标准静态分析结果格式，内容更完整，适合工具读取。

里面通常包括：

- 查询规则信息
- 告警位置
- 告警消息
- 严重程度
- 如果是路径型查询，还会有 `codeFlows`

例如命令注入中，CodeQL 可能会记录：

```text
request.args["cmd"]
-> command
-> os.system(command)
```

### `results.csv`

CSV 是更适合人快速查看的表格格式。

通常一行是一条告警，常见字段包括：

```text
规则标题, 规则描述, 严重级别, 告警消息, 文件路径, 起始行, 起始列, 结束行, 结束列
```

如果查询成功执行但没有发现漏洞，`results.csv` 可能是空文件。

这不一定是错误，可能只是没有结果。

## 七、已验证的 smoke test

本地曾用一个 Flask 风格的最小样例验证过：

```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run_from_request():
    command = request.args["cmd"]
    os.system(command)
    return "ok"
```

运行：

```bash
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language python \
  --overwrite \
  iris-python-smoke
```

确认结果：

- SARIF 中有 `1` 条 result
- 规则为 `py/command-line-injection`
- 告警位置为 `os.system(command)`
- CSV 不为空

这说明当前 Python 原生 CodeQL 路线已经能跑出真实漏洞告警。

## 八、当前支持范围

当前支持的是：

```text
CodeQL Python 查询包中已有的稳定 CWE 查询目录
```

例如这类路径：

```text
codeql/qlpacks/codeql/python-queries/<version>/Security/CWE-078/
```

只要目录存在，就可以使用：

```bash
--query cwe-078wCodeQL --language python
```

暂时不处理：

- 一键运行完整 CodeQL suite
- Python 版 LLM source/sink/parameter 标注

experimental 查询处理规则：

- `cwe-XXXwCodeQL`：优先使用稳定目录；如果稳定目录不存在，会自动 fallback 到 `experimental/Security/...`。
- `cwe-XXXwCodeQLExp`：明确使用 `experimental/Security/...`，适合想强制跑实验查询的场景。
