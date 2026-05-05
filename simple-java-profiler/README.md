# 简单 Java 性能分析工具

## 介绍

这是一个从原始 DeepFlow agent 中简化和提取的 Java 性能分析工具。提供了两种方案：
1. **独立 C 程序方案** - 无需注入 agent，使用 perf 直接采样
2. **JVMTI Agent 方案** - 原始但简化的注入方案

## 快速开始

### 1. 编译

```bash
cd /workspace/simple-java-profiler
make
chmod +x run_profiler.sh
```

### 2. 一键运行（推荐）

```bash
# 使用5秒采样
./run_profiler.sh 5
```

### 3. 或者分步运行

#### 方案A: 简单的JVMTI Agent

```bash
# 1. 启动Java程序并加载agent
java -agentpath:./libsimple_agent_file.so TestProgram

# 2. 在另一个终端查看符号文件
cat /tmp/perf-simple.map
```

#### 方案B: 使用 perf 分析

```bash
# 1. 启动Java程序（加载agent生成符号）
java -agentpath:./libsimple_agent_file.so TestProgram &
JAVA_PID=$!

# 2. 等待符号生成
sleep 2

# 3. 使用perf采样（需要root权限）
perf record -F 99 -g -p $JAVA_PID -o perf.data -- sleep 5

# 4. 复制符号文件并解析
cp /tmp/perf-simple.map ./
perf script -i perf.data > perf.script.txt
./symbol_parser perf-simple.map perf.script.txt

# 5. 查看分析结果
cat profiler.folded
```

## 组件说明

| 文件 | 功能 |
|------|------|
| TestProgram.java | 一个测试用的Java程序 |
| simple_agent.c | 基础JVMTI Agent，打印到stdout |
| simple_agent_file.c | JVMTI Agent，写入perf map文件 |
| symbol_parser.c | 解析符号和perf脚本的工具 |
| standalone_profiler.c | （实验性）使用perf_event直接采样 |
| run_profiler.sh | 一键测试脚本 |
| Makefile | 编译配置 |

## 与原项目的区别

| 原项目 | 本项目 |
|--------|--------|
| 完整的Agent系统 | 最小化的测试用例 |
| Unix Socket通信 | 直接写文件或stdout |
| 多线程架构 | 单线程，简单实现 |
| 命名空间支持 | 仅本地运行 |
| 完整的符号收集 | 基本的JIT符号捕获 |

## 原项目架构参考

原项目 `/workspace/agent` 的 Java Profiler 组件：

```
/workspace/agent/src/ebpf/user/profile/java/
├── symbol_collect_agent.c  # JVMTI Agent代码
├── jvm_symbol_collect.c     # 符号收集管理
├── jvm_symbol_collect.h     # 头文件
└── config.h                 # 配置
```

核心流程：
1. JVMTI Agent注入到目标JVM进程
2. 监听 `CompiledMethodLoad` 和 `DynamicCodeGenerated` 事件
3. 捕获JIT编译的方法地址和符号
4. 通过Unix Socket传递给Agent进程
5. 保存为 `/tmp/perf-<pid>.map`

## 生成火焰图

```bash
# 下载FlameGraph工具
git clone https://github.com/brendangregg/FlameGraph

# 生成火焰图
perf script -i perf.data | FlameGraph/stackcollapse-perf.pl > profiler.folded
FlameGraph/flamegraph.pl profiler.folded > profiler.svg

# 用浏览器查看SVG
```

## 配置要求

- Linux 系统
- OpenJDK / Oracle JDK 8+
- perf 工具（可选，推荐）
- gcc 编译器
