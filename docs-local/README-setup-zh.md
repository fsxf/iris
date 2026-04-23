# IRIS 中文配置与使用说明

这份文档用于说明：在不上传本地环境、缓存、运行结果和密钥的前提下，别人拿到这个仓库后，如何在自己的机器上把 IRIS 配起来并跑通。

这份说明默认面向：

- Linux 或 WSL Ubuntu 环境
- 需要运行 IRIS 的 Java 流程
- 使用 DeepSeek 远程 API 作为 LLM 后端

如果你使用的是 macOS，整体思路相同，但 JDK、Maven、Gradle 和 CodeQL 的安装路径需要按你自己的系统调整。

## 一、仓库里不包含什么

为了避免仓库过大，也避免把本地敏感信息或运行产物上传到 GitHub，下面这些内容默认不应提交：

- 本地 Conda 环境
- 本地安装的 JDK / Maven / Gradle
- 下载的安装包和缓存
- CodeQL 数据库
- 分析输出结果
- 日志
- API Key

因此，拿到仓库后，需要在本地重新完成环境配置。

## 二、你需要准备什么

运行 IRIS 的 Java 流程，至少需要这些依赖：

- Conda
- Python 环境 `iris`
- CodeQL
- Java 构建工具：
  - JDK
  - Maven
  - Gradle
- 一个可用的 LLM 后端

这份仓库已经支持使用 DeepSeek 远程 API，因此不强制要求你在本地部署大模型。

## 三、推荐的目录组织方式

建议把运行依赖放在仓库内部或你自己可控的目录中，然后在本地修改配置文件指向它们。

例如：

```text
iris/
├── .miniconda3/
├── .tools/
│   ├── jdks/
│   ├── maven/
│   └── gradle/
├── codeql/
├── src/
├── scripts/
└── ...
```

这样做的好处是：

- 路径清晰
- 方便迁移
- 不依赖系统全局安装

## 四、环境配置步骤

### 1. 创建 Conda 环境

在仓库根目录执行：

```bash
conda env create -f environment.yml
conda activate iris
```

如果你的机器没有 `conda`，需要先自行安装 Miniconda 或 Anaconda。

### 2. 安装 Java 构建工具

IRIS 跑 Java 项目时，需要根据具体项目使用不同版本的 JDK、Maven、Gradle。

以 README 示例项目 `perwendel__spark_CVE-2018-9159_2.7.1` 为例，它至少需要：

- JDK 8
- Maven 3.5.0

为了兼容更多项目，建议准备：

- JDK 8 / 11 / 17
- Maven 3.2.1 / 3.5.0 / 3.9.8
- Gradle 6.8.2

你可以自己用 SDKMAN、手工解压、或任何你习惯的方式安装这些工具。

### 3. 修改 `dep_configs.json`

安装好工具后，需要修改仓库根目录下的：

- `dep_configs.json`
- `dep_configs.linux_x64.json`

把里面的路径改成你自己机器上的真实路径。

例如，这类路径需要按你的本地环境填写：

- JDK 路径
- Maven 路径
- Gradle 路径

注意：

- 这两个文件是“本地环境配置文件”
- 不同机器上的路径几乎一定不同
- 如果你要把代码推到 GitHub，最好不要把你个人机器上的绝对路径当成通用配置

### 4. 安装 CodeQL

当前本地验证使用 CodeQL 2.25.2。相比原 README 推荐的 2.23.2，新版 bundle 自带更新的 `python-queries`、`cpp-queries` 和 `java-queries`，可以覆盖更多 CodeQL 原生查询。

当前已验证的本地版本信息：

```text
CodeQL command-line toolchain release 2.25.2
python-queries: 1.8.0
cpp-queries: 1.6.0
java-queries: 1.11.0
java-all: 9.0.3
```

如果替换 CodeQL 版本，需要同步确认 `src/config.py` 中的 `CODEQL_QUERY_VERSION` 是否匹配新版 `codeql/qlpacks/codeql/java-all/<version>`。当前已设置为：

```text
CODEQL_QUERY_VERSION = "9.0.3"
```

下载 CodeQL bundle 后，把它解压到仓库根目录，形成：

```text
codeql/codeql
```

然后在运行前把它加入 `PATH`：

```bash
export PATH="$PWD/codeql:$PATH"
```

## 五、DeepSeek 远程 API 配置

这份仓库已经支持通过 DeepSeek 远程 API 运行 IRIS，不需要本地部署 7B 模型。

相关实现位于：

- `src/models/deepseek.py`

支持的远程模型名包括：

- `deepseek-chat`
- `deepseek-reasoner`

### 1. 配置云端模型

建议在仓库根目录新建一个本地文件：

```text
cloud_config.json
```

内容示例：

```json
{
  "key": "你的 API Key",
  "url": "https://api.deepseek.com",
  "model": "deepseek-chat"
}
```

其中 `key` 是密钥，`url` 是 OpenAI 兼容接口地址，`model` 是实际发送给云端的模型名。

运行命令里的 `--llm deepseek-chat` 仍然保留，它的作用是让 IRIS 进入 DeepSeek 远程 API 适配器；真正请求云端时使用的是 `cloud_config.json` 里的 `model` 字段。

## 六、如何跑通 README 里的示例项目

示例项目是：

- `perwendel__spark_CVE-2018-9159_2.7.1`

完整流程如下。

### 第 1 步：抓取并构建项目

```bash
python scripts/fetch_and_build.py --filter perwendel__spark_CVE-2018-9159_2.7.1 --verbose
```

这一步会：

- 拉取对应项目源码
- 切换到数据集指定的漏洞版本
- 使用 IRIS 所需的 JDK / Maven / Gradle 构建项目

成功后，相关内容通常会出现在：

- `data/project-sources/`
- `data/build-info/`

### 第 2 步：生成 CodeQL 数据库

```bash
python scripts/build_codeql_dbs.py --project perwendel__spark_CVE-2018-9159_2.7.1
```

成功后，数据库会出现在：

- `data/codeql-dbs/perwendel__spark_CVE-2018-9159_2.7.1/`

### 第 3 步：确认云端模型配置

确认仓库根目录存在 `cloud_config.json`，并且包含 `key`、`url`、`model` 三个字段。

### 第 4 步：运行 IRIS 分析

```bash
python src/iris.py \
  --query cwe-022wLLM \
  --run-id test-deepseek \
  --llm deepseek-chat \
  perwendel__spark_CVE-2018-9159_2.7.1
```

这里和原 README 的区别在于：

- 原 README 使用本地 `qwen2.5-coder-7b`
- 这里改为使用远程 `deepseek-chat`

## 七、运行结果在哪里看

这次运行完成后，核心结果通常会出现在：

- `output/<project>/<run-id>/`

以示例项目为例，就是：

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/`

最重要的产物包括：

### 1. 总日志

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/log/`

### 2. 原始 CodeQL 结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM/results.csv`
- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM/results.sarif`

### 3. LLM 标注结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/analysis/cwe-022wLLM/`

### 4. 自动生成的 CodeQL 查询

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/myqueries/cwe-022wLLM/`

### 5. 最终汇总结果

- `output/perwendel__spark_CVE-2018-9159_2.7.1/test-deepseek/cwe-022wLLM-final/results.json`

如果只是想快速看这次分析的最终统计，这个 `results.json` 最值得先看。
