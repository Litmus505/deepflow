# 简单 Java Profiler 实现

这是一个极简的 Java 性能分析工具实现，基于 JVMTI (JVM Tool Interface)。

## 目录结构

```
simple-java-profiler/
├── TestProgram.java       # 测试用的 Java 程序
├── simple_agent.c         # 基础 JVMTI Agent（打印到标准输出）
├── simple_agent_file.c    # 实用版本（写入 perf map 文件）
├── receiver.c             # 可选的接收端程序
├── Makefile               # 编译文件
└── README.md              # 本说明文档
```

## 工作原理

1. **JVMTI Agent**：通过 JVMTI 接口监听 JVM 的编译事件
2. **符号收集**：当方法被 JIT 编译时，获取其地址和符号信息
3. **符号文件**：将符号信息写入 `/tmp/perf-simple.map`，格式与 perf 工具兼容

## 编译

```bash
# 需要先设置 JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64  # 根据实际情况调整

# 编译所有组件
make
```

## 快速测试

### 方法 1：使用简单文件输出 Agent（推荐）

这是最简单的方法，直接将符号写入文件：

```bash
# 编译完成后，运行 Java 程序并加载 Agent
java -agentpath:./libsimple_agent_file.so TestProgram
```

然后在另一个终端查看生成的符号文件：
```bash
cat /tmp/perf-simple.map
```

### 方法 2：仅打印到标准输出

```bash
java -agentpath:./libsimple_agent.so TestProgram
```

## 符号文件格式

生成的 `/tmp/perf-simple.map` 文件格式与 Linux perf 工具兼容：

```
<地址> <大小> <符号名>
```

例如：
```
7f4a3c123456 1234 TestProgram.methodA
7f4a3c124567 2345 TestProgram.sortArray
```

## 集成到 perf（可选）

有了符号文件后，你可以使用 perf 进行性能分析：

```bash
# 1. 运行 Java 程序
java -agentpath:./libsimple_agent_file.so TestProgram &
PID=$!

# 2. 等待几秒让 JIT 编译完成
sleep 5

# 3. 使用 perf record 采样
perf record -p $PID -g -F 99 -- sleep 10

# 4. 使用 perf report 查看结果（符号会自动解析）
perf report
```

## 清理

```bash
make clean
```

## 与原项目的关系

这个简化版本基于 `/workspace/agent` 目录中的 Java profiling 实现，但进行了大量简化：

- 移除了复杂的 Unix 域套接字通信
- 移除了线程池和任务管理
- 移除了命名空间支持
- 保留了核心的 JVMTI 事件监听和符号收集功能
