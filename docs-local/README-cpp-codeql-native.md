# IRIS C/C++ CodeQL 原生查询路线说明

本文说明当前项目中新增的 C/C++ CodeQL 原生查询路线：它不依赖 IRIS 原本的 LLM source/sink 打标签流程，而是直接使用 CodeQL 自带的 C/C++ 查询包运行安全查询。

## 为什么 C/C++ 需要特别处理

C/C++ 和 Python 不一样。Python 通常可以直接扫描源码创建数据库，而 C/C++ 项目往往需要编译，CodeQL 需要在编译过程中捕获编译命令、宏、include 路径和预处理后的信息。

因此当前 C/C++ 路线支持两种建库方式：

- 推荐方式：提供真实构建命令，例如 `make`、`cmake --build build`，适合真实项目。
- 兜底方式：不提供构建命令时使用 `build-mode=none`，适合很小的 smoke sample 或快速检查，但对复杂项目和部分 taint 查询可能不完整。


## 相关改动

本轮主要改动如下：

- `src/language_config.py` 新增 `cpp` 语言配置，对应 CodeQL 查询包 `cpp-queries`、数据库目录 `db-cpp`、查询目录 `Security/CWE/CWE-{cwe_id}`。
- `scripts/build_codeql_dbs.py` 新增 `--language cpp`，并新增 `--command` 用于传入 C/C++ 构建命令。
- `scripts/build_codeql_dbs.py` 新增 `--build-mode none`，当 C/C++ 未提供构建命令时默认使用 CodeQL buildless 建库。
- `src/codeql_vul.py` 新增 `--language cpp`，输出目录为 `output/<project>/codeql-cpp/<query>/`。
- `src/codeql_vul.py` 支持未写入 `queries.py` 的 `cwe-XXXwCodeQL` 和 `cwe-XXXwCodeQLExp` 查询名，会自动解析 CWE id 并寻找 CodeQL 自带查询目录。
- `cwe-XXXwCodeQL` 会优先使用稳定查询目录；如果稳定目录不存在，会自动 fallback 到 `experimental/Security/...`。
- `cwe-XXXwCodeQLExp` 会明确使用 experimental 查询目录。

## 环境准备

真实 C/C++ 项目推荐安装 Linux 侧编译工具链。

如果你有 sudo 权限，可以在 WSL 里执行：

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config
```

检查：

```bash
gcc --version
g++ --version
make --version
cmake --version
```

如果不能或不想装系统级工具链，也可以安装 Conda 工具链作为备选：

```bash
HOME=/home/lifew/iris /home/lifew/iris/.miniconda3/bin/conda install -y -n iris --override-channels -c conda-forge gcc_linux-64 gxx_linux-64 make
```

Conda 工具链的编译器名通常不是 `gcc`，而是：

```bash
x86_64-conda-linux-gnu-gcc
x86_64-conda-linux-gnu-g++
```

## 使用方式

假设项目源码位于：

```text
data/project-sources/<project_slug>/
```

创建 C/C++ CodeQL 数据库：

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py \
  --project <project_slug> \
  --language cpp \
  --command "make"
```

如果是 CMake 项目，常见写法是：

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py \
  --project <project_slug> \
  --language cpp \
  --command "cmake --build build"
```

如果需要先配置再编译，可以把构建步骤封装到脚本里，例如 `build.sh`，然后传：

```bash
--command "bash build.sh"
```

对于 Conda 工具链，可以显式指定编译器：

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py \
  --project <project_slug> \
  --language cpp \
  --command "make clean all CC=x86_64-conda-linux-gnu-gcc"
```

运行 CodeQL 原生查询：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language cpp \
  --overwrite \
  <project_slug>
```

如果某个 CWE 只有 experimental 查询，也可以直接使用普通命令，让程序自动 fallback：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-415wCodeQL \
  --language cpp \
  --overwrite \
  <project_slug>
```

日志中会出现类似提示：

```text
Stable CodeQL query not found; falling back to experimental query: ...
```

如果想强制使用 experimental 查询，可以使用：

```bash
--query cwe-415wCodeQLExp
```

## 当前 smoke 验证

本地 smoke 项目路径：

```text
data/project-sources/iris-cpp-smoke/
```

其中 `main.c` 包含一个命令注入样例：

```c
char command[1000] = {0};
sprintf(command, "userinfo -v \"%s\"", argv[1]);
system(command);
```

使用系统级 gcc/make 建库：

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py \
  --project iris-cpp-smoke \
  --language cpp \
  --command "make clean all"
```

运行查询：

```bash
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python src/codeql_vul.py \
  --query cwe-078wCodeQL \
  --language cpp \
  --overwrite \
  iris-cpp-smoke
```

已验证产物：

```text
output/iris-cpp-smoke/codeql-cpp/cwe-078wCodeQL/results.csv
output/iris-cpp-smoke/codeql-cpp/cwe-078wCodeQL/results.sarif
```

`results.csv` 中出现 1 条真实告警，含义是：

- 规则：`Uncontrolled data used in OS command`
- CWE：CWE-078，命令注入
- source：`argv[1]`，命令行参数
- 中间流：`sprintf(command, ...)`
- sink：`system(command)`，位置为 `main.c:8`

如果使用的是 Conda 工具链，也已验证下面的命令同样可用：

```bash
PATH=/home/lifew/iris/codeql:$PATH \
HOME=/home/lifew/iris \
/home/lifew/iris/.miniconda3/bin/conda run -n iris \
python scripts/build_codeql_dbs.py \
  --project iris-cpp-smoke \
  --language cpp \
  --command "make clean all CC=x86_64-conda-linux-gnu-gcc"
```

## 产物怎么看

数据库产物：

```text
data/codeql-dbs/<project_slug>/db-cpp/
```

查询结果：

```text
output/<project_slug>/codeql-cpp/<query>/results.csv
output/<project_slug>/codeql-cpp/<query>/results.sarif
```

`results.csv` 适合快速查看告警摘要，通常包含规则名、描述、严重级别、告警消息、文件路径、起止行列。

`results.sarif` 是 CodeQL 标准结果格式，信息更完整，包含 rule id、location、message、codeFlows 等。对于 path-problem 查询，SARIF 里能看到从 source 到 sink 的路径。

## 注意事项

- C/C++ 真实项目优先使用 `--command`，不要依赖 `build-mode=none` 做最终判断。
- Windows 下的 MinGW `gcc.exe` 不能直接作为 WSL/Linux CodeQL 的编译捕获目标；推荐使用 WSL 内的 gcc/make/cmake。
- 如果项目依赖复杂，先确保项目能在 WSL 里独立编译成功，再交给 CodeQL 建库。
- 当前路线只做 CodeQL 原生查询，没有进入 IRIS 的 LLM 终审阶段；后续可以在这个结果基础上继续接入 LLM posthoc filtering。
