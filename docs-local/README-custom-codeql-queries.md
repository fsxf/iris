# 自定义 CodeQL 查询接入说明

本文说明当前项目如何接入自定义 CodeQL 查询脚本。

## 一、为什么不放进 codeql 目录

项目内 `codeql/` 是官方 CodeQL bundle，已经被 `.gitignore` 忽略，不适合放自定义规则。否则本机能跑，但别人 fork 仓库后拿不到这些查询脚本。

因此自定义查询统一放在可提交目录：

```text
src/native-codeql-queries/
```

官方查询和自定义查询的命令也分开：

```text
cwe-XXXwCodeQL        -> CodeQL 官方查询
cwe-XXXwCodeQLCustom  -> 项目内自定义查询
```

## 二、当前目录结构

```text
src/native-codeql-queries/
  python/
    qlpack.yml
    cwe-319/CleartextSensitiveHttp.ql
    cwe-369/DivideByZero.ql
    cwe-434/UnrestrictedFileUpload.ql
    cwe-676/PotentiallyDangerousFunction.ql

  cpp/
    qlpack.yml
    cwe-434/UnrestrictedFileUpload.ql
    cwe-434/CppCweHeuristics.qll
    cwe-532/SensitiveInfoLog.ql
    cwe-532/CppCweHeuristics.qll
    cwe-798/HardcodedCredentials.ql
    cwe-798/CppCweHeuristics.qll

  java/
    qlpack.yml
    cwe-369/DivideByZero.ql
    cwe-434/UnrestrictedFileUpload.ql
```

## 三、problem 和 path-problem 状态

当前自定义查询分两类：

- `@kind path-problem`：SARIF 里可以包含 `codeFlows`，后续可以进入 native posthoc 做路径级 LLM 判断。
- `@kind problem`：只报告一个告警位置，通常没有 `codeFlows`，不适合路径级 posthoc。

已经是 `path-problem` 的查询：

```text
python/cwe-319/CleartextSensitiveHttp.ql
python/cwe-434/UnrestrictedFileUpload.ql
cpp/cwe-434/UnrestrictedFileUpload.ql
cpp/cwe-532/SensitiveInfoLog.ql
java/cwe-434/UnrestrictedFileUpload.ql
```

仍保留为 `problem` 的查询：

```text
python/cwe-369/DivideByZero.ql
python/cwe-676/PotentiallyDangerousFunction.ql
cpp/cwe-798/HardcodedCredentials.ql
java/cwe-369/DivideByZero.ql
```

这些保留为 `problem` 是有意的：除零、危险函数调用、硬编码凭证更像单点模式匹配或局部结构告警，没有自然的 source -> sink 数据流。强行改成 `path-problem` 会制造不真实的路径，反而影响后续 LLM 后审可信度。

## 四、如何运行

先确保对应语言的 CodeQL 数据库已经存在，例如：

```text
data/codeql-dbs/<project>/db-python
data/codeql-dbs/<project>/db-cpp
data/codeql-dbs/<project>/db-java
```

运行 Python 自定义 CWE-319：

```bash
python src/codeql_vul.py \
  --query cwe-319wCodeQLCustom \
  --language python \
  <project>
```

运行 C/C++ 自定义 CWE-798：

```bash
python src/codeql_vul.py \
  --query cwe-798wCodeQLCustom \
  --language cpp \
  <project>
```

运行 Java 自定义 CWE-434 时，如果不是 CWE-Bench Java 数据集项目，建议加 `--skip-evaluation`：

```bash
python src/codeql_vul.py \
  --query cwe-434wCodeQLCustom \
  --language java \
  --skip-evaluation \
  <project>
```

## 五、产物位置

Python：

```text
output/<project>/codeql-python/cwe-XXXwCodeQLCustom/results.csv
output/<project>/codeql-python/cwe-XXXwCodeQLCustom/results.sarif
```

C/C++：

```text
output/<project>/codeql-cpp/cwe-XXXwCodeQLCustom/results.csv
output/<project>/codeql-cpp/cwe-XXXwCodeQLCustom/results.sarif
```

Java：

```text
output/<project>/common/cwe-XXXwCodeQLCustom/results.csv
output/<project>/common/cwe-XXXwCodeQLCustom/results.sarif
```

