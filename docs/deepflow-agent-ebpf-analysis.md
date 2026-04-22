# DeepFlow Agent 功能实现机制深度解析

## 目录

- [1. 总体架构](#1-总体架构)
- [2. eBPF 子系统架构](#2-ebpf-子系统架构)
- [3. AutoMetrics 实现机制](#3-autometrics-实现机制)
- [4. AutoTracing 实现机制](#4-autotracing-实现机制)
- [5. AutoProfiling 实现机制](#5-autoprofiling-实现机制)
- [6. cBPF/AF_PACKET 采集机制](#6-cbpfaf_packet-采集机制)
- [7. TLS/SSL 加密流量追踪](#7-tlsssl-加密流量追踪)
- [8. Go 语言运行时专项追踪](#8-go-语言运行时专项追踪)
- [9. Wasm 插件机制](#9-wasm-插件机制)
- [10. 数据流水线与处理链路](#10-数据流水线与处理链路)
- [11. 内核版本兼容性策略](#11-内核版本兼容性策略)
- [12. 性能与资源管理](#12-性能与资源管理)

---

## 1. 总体架构

DeepFlow Agent 采用 **Rust 语言**编写主体逻辑，通过 FFI（Foreign Function Interface）调用底层 **C 语言 libtrace 库**（位于 `agent/src/ebpf/`），后者负责管理 eBPF 程序的编译、加载和 BPF Maps 的操作。

```
┌─────────────────────────────────────────────────────────┐
│                  DeepFlow Agent (Rust)                   │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │EbpfDispatcher│  │ Dispatcher  │  │  Collector    │  │
│  │ (ebpf数据入口)│  │ (网络包入口) │  │ (指标聚合)    │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬────────┘  │
│         │               │                  │           │
│  ┌──────▼───────────────▼──────────────────▼────────┐  │
│  │              FlowMap / FlowGenerator              │  │
│  │        (流表管理 / L4-L7协议解析 / 指标计算)       │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌────────────────────────┐  ┌────────────────────────┐ │
│  │  eBPF C Library        │  │  Wasm Plugin Engine    │ │
│  │  (libtrace, FFI调用)   │  │  (自定义协议解析)      │ │
│  └──────────┬─────────────┘  └────────────────────────┘ │
└─────────────┼───────────────────────────────────────────┘
              │ BPF Maps / Perf Event
┌─────────────▼───────────────────────────────────────────┐
│                   Linux Kernel                           │
│  ┌──────────┐ ┌───────────┐ ┌─────────────┐            │
│  │ kprobes  │ │tracepoints│ │  uprobes    │            │
│  │kretprobes│ │           │ │ uretprobes  │            │
│  └──────────┘ └───────────┘ └─────────────┘            │
│  ┌──────────────────────────────────────────────┐       │
│  │         Socket Trace BPF Programs            │       │
│  │     (socket_trace.bpf.c / openssl.bpf.c)    │       │
│  └──────────────────────────────────────────────┘       │
│  ┌──────────────────────────────────────────────┐       │
│  │         Perf Profiler BPF Programs           │       │
│  │          (perf_profiler.bpf.c)               │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

---

## 2. eBPF 子系统架构

### 2.1 目录结构

```
agent/src/ebpf/
├── kernel/              # eBPF 内核态程序（BPF C 代码）
│   ├── socket_trace.bpf.c       # 套接字追踪核心逻辑
│   ├── perf_profiler.bpf.c      # 性能剖析采样逻辑
│   ├── openssl.bpf.c            # OpenSSL uprobe 处理
│   ├── go_tls.bpf.c             # Go TLS uprobe 处理
│   ├── go_http2.bpf.c           # Go HTTP/2 uprobe 处理
│   └── include/
│       ├── socket_trace.h       # 核心数据结构定义
│       ├── protocol_inference.h # 协议推断逻辑（分3段以规避指令数限制）
│       ├── perf_profiler.h      # 性能剖析数据结构
│       └── common.h             # 公共宏、辅助函数
│
└── user/                # 用户态 C 库（libtrace）
    ├── tracer.c/h               # Tracer 核心管理
    ├── socket.c/h               # Socket Tracer 主入口
    ├── go_tracer.c/h            # Go 程序 uprobe 管理
    ├── ssl_tracer.c/h           # OpenSSL uprobe 管理
    ├── unwind_tracer.c/h        # DWARF 栈展开
    ├── profile/
    │   ├── perf_profiler.c/h    # On-CPU 性能剖析器
    │   └── stringifier.c/h      # 符号化处理
    └── offset.c/h               # 内核结构体偏移推断
```

### 2.2 Tracer 状态机

用户态 Tracer 具有完整的生命周期状态管理：

```
TRACER_INIT
    │ 初始化完成
    ▼
TRACER_WAIT_START
    │ 调用 socket_tracer_start()
    ▼
TRACER_RUNNING ←──── 可暂停 ────► TRACER_WAIT_STOP
    │                                     │
    │ 出错                                 │ 调用 socket_tracer_stop()
    ▼                                     ▼
TRACER_START_ERR                    TRACER_STOP
                                         │
                                    TRACER_STOP_ERR（出错时）
```

### 2.3 探针优先级策略

Agent 会自动检测内核特性，按如下优先级选择探针类型，以达到最优性能：

| 优先级 | 探针类型 | 说明 |
|--------|----------|------|
| 最高 | `fentry/fexit` | 内核 5.5+ BPF trampolines，开销最低 |
| 次之 | `tracepoint` | 内核 4.7+ 稳定接口，兼容性好 |
| 次之 | `kprobe/kretprobe` | 内核 4.1+ 动态探针，通用性强 |
| 仅用于用户态 | `uprobe/uretprobe` | 用户态程序探针，开销较高 |

探针开销参考（BPF 每事件纳秒）：

| 类型 | 开销(ns) |
|------|----------|
| kprobe | 76 |
| kretprobe | 212 |
| tracepoint(entry) | 96 |
| tracepoint(exit) | 93 |
| uprobe | 1287 |
| uretprobe | 1931 |

---

## 3. AutoMetrics 实现机制

### 3.1 基于 eBPF 的 Socket 追踪（Linux 4.14+）

**核心原理**：在 Linux 系统调用层面注入 eBPF 探针，无侵入地捕获所有进程的网络 I/O 数据，并在内核态完成协议识别和数据提取，通过 Perf Event 将结果传递到用户态。

#### 3.1.1 挂载点覆盖

系统调用级的 Kprobe/Tracepoint 覆盖了所有主要 socket I/O 接口：

**Tracepoints（稳定 ABI）：**
- `sys_enter_write` / `sys_exit_write`
- `sys_enter_read` / `sys_exit_read`
- `sys_enter_sendto` / `sys_exit_sendto`
- `sys_enter_recvfrom` / `sys_exit_recvfrom`
- `sys_enter_sendmsg` / `sys_exit_sendmsg`
- `sys_enter_sendmmsg` / `sys_exit_sendmmsg`
- `sys_enter_recvmsg` / `sys_exit_recvmsg`
- `sys_enter_recvmmsg` / `sys_exit_recvmmsg`
- `sys_exit_writev` / `sys_exit_readv`
- `sys_exit_accept` / `sys_exit_accept4`
- `sys_exit_socket`
- `sys_enter_close`

**Kprobes（用于低版本内核或特殊接口）：**
- `__sys_sendmsg`, `__sys_sendmmsg`, `__sys_recvmsg`
- `sys_writev` / `do_writev`, `sys_readv` / `do_readv`（兼容 3.10）

#### 3.1.2 内核态数据处理流程

```
系统调用入口（entry hook）
    │
    ├─ 保存参数（用户态 buffer 地址、fd 等）到 active_args_map
    │
系统调用出口（exit hook）
    │
    └─ process_syscall_data()
           │
           ├─ process_data()
           │      ├─ is_tcp_udp_data()   → 过滤非 TCP/UDP
           │      ├─ init_conn_info()    → 初始化连接信息（五元组）
           │      └─ infer_l7_class()    → 触发协议推断（Tail Call）
           │
           └─ infer_protocol()（分 3 段 Tail Call，规避指令数限制）
                  ├─ check_data()        → 校验 sk_type, sk_state
                  ├─ drop_msg_by_comm()  → 过滤 ssh/sshd 等
                  └─ infer_message()     → 协议特征匹配
                         │
                         └─ data_submit()（协议匹配成功）
                                ├─ 计算 TCP SEQ
                                ├─ 分配/更新 socket_info（socket_info_map）
                                ├─ 生成 trace_id（trace_map）
                                └─ burst 方式推送到 perf event buffer
```

**Tail Call 优化**：为绕过内核 eBPF 验证器的单程序最大 4096/100 万条指令限制，协议推断被拆分成 3 个 BPF 程序，通过 `BPF_MAP_TYPE_PROG_ARRAY`（`progs_jmp_kp_map`/`progs_jmp_tp_map`）实现 Tail Call 串联。

#### 3.1.3 关键 BPF Maps

| Map 名称 | 类型 | 作用 |
|----------|------|------|
| `__socket_data` | PERF_EVENT_ARRAY | 内核→用户态数据传输通道 |
| `__data_buf` | PERCPU_ARRAY | Burst 发送缓存（16KB/CPU） |
| `__active_write_args_map` | HASH | 保存 write 系统调用入参 |
| `__active_read_args_map` | HASH | 保存 read 系统调用入参 |
| `__socket_info_map` | HASH(pid+fd) | Socket 连接状态（协议/方向/序号等） |
| `__trace_map` | HASH(tgid+pid) | 追踪会话（线程级 trace context） |
| `__tracer_ctx_map` | PERCPU_ARRAY | Tracer 配置（UID 初始值等） |
| `__members_offset` | PERCPU_ARRAY | 内核结构体成员偏移（自动推断/BTF） |
| `__proto_infer_cache_map` | ARRAY | 协议推断快速缓存（Linux 5.2+） |
| `__allow_reasm_protos_map` | ARRAY | 允许分片重组的协议集合 |
| `__kprobe_port_bitmap` | ARRAY | 端口过滤位图 |
| `__protocol_filter` | ARRAY | 启用/禁用特定 L7 协议 |

#### 3.1.4 支持的 L7 协议

共支持 **30+ 种**应用层协议的自动识别：

| 分类 | 协议 |
|------|------|
| Web | HTTP/1, HTTP/2, HTTPS(TLS) |
| RPC | Dubbo, SofaRPC, bRPC, Tars, gRPC, SOME/IP |
| 数据库 | MySQL, PostgreSQL, Oracle, Redis, MongoDB, Memcached |
| 消息队列 | Kafka, MQTT, AMQP(RabbitMQ), RocketMQ, OpenWire, NATS, Pulsar, ZMTP |
| 其他 | DNS, FastCGI, ISO-8583, TLS(握手), Custom(Wasm扩展) |

### 3.2 数据结构：socket_bpf_data

从内核传递到用户态的每条 Socket 数据包含完整上下文：

```c
struct socket_bpf_data {
    uint32_t process_id;       // 进程 TGID
    uint32_t thread_id;        // 线程 PID
    uint64_t coroutine_id;     // Go 协程 ID
    uint8_t  source;           // 来源：syscall/go_tls/go_http2
    struct __tuple_t tuple;    // 五元组（src/dst IP、端口、L4 协议）
    uint64_t socket_id;        // Socket 唯一 ID（单调递增）
    uint16_t l7_protocal_hint; // 推断的 L7 协议类型
    uint8_t  msg_type;         // 请求/响应/未知
    uint64_t tcp_seq;          // TCP 序列号（用于关联 pcap 数据）
    uint64_t syscall_trace_id_call; // 追踪 ID（协程/线程级）
    uint64_t timestamp;        // 系统调用时间戳（纳秒）
    uint8_t  direction;        // 发送/接收方向
    uint64_t syscall_len;      // 系统调用读写总字节数
    uint32_t cap_len;          // 实际捕获的数据长度（≤16KB）
    char    *cap_data;         // 捕获的应用层数据
};
```

---

## 4. AutoTracing 实现机制

### 4.1 分布式调用链追踪原理

AutoTracing 的核心挑战是**在不修改任何业务代码的前提下**，将分布在不同进程乃至不同机器上的 Request/Response 关联成完整的调用链。

#### 4.1.1 线程/协程级 Trace ID 生成

在内核 eBPF 程序中，通过 `__trace_map` 维护线程/协程的追踪上下文：

```
[进程 A: 线程 T1] 收到 Request
    │
    ├─ eBPF 在 sys_enter_recvfrom 时记录 trace_map[tgid+pid]
    │    = 新生成的 thread_trace_id
    │
    └─ 当 T1 发出 Request（sys_enter_sendto）时
         └─ 从 trace_map 取出 thread_trace_id 附加到发出的数据
              └─ 删除 trace_map 条目（单次使用）
```

这样，同一线程/协程在处理一个请求期间，收到的 Request 与发出的 Request 会被标记相同的 `syscall_trace_id_call`，在用户态可以关联成父子调用关系。

#### 4.1.2 TCP SEQ 关联

每条 socket_bpf_data 中都携带了 **TCP 序列号**（`tcp_seq`），这使得 eBPF 采集的应用层数据可以与 cBPF/AF_PACKET 采集的网络包精确对应，实现跨采集面的数据关联。

#### 4.1.3 Go 协程 ID 追踪

针对 Go 语言的 M:N 协程模型，Agent 专门维护了协程 ID 的传播：

- `goroutines_map`（HASH）：维护线程 PID → 协程 ID 映射
- `go_ancerstor_map`（LRU HASH）：维护父子协程的继承关系
- 在 `runtime.newproc1` 入口/出口的 uprobe 中，捕获新协程创建事件，建立父子关系链

#### 4.1.4 Wasm Plugin 自定义追踪

对于 cBPF 场景（不支持 eBPF 的环境），Agent 提供 Wasm Plugin 接口，允许业务方编写解析逻辑来提取私有协议中的**业务流水号**，并将其作为追踪 ID 关联分布式调用链。Wasm 引擎通过 FFI 与 Rust 主进程交互（详见 §9）。

---

## 5. AutoProfiling 实现机制

### 5.1 On-CPU 持续性能剖析（Linux 4.9+）

#### 5.1.1 基于 Perf Event 的采样原理

Agent 利用 Linux 的 **PMU（性能监控单元）Perf Events** 机制，以固定频率对所有 CPU 上的运行中进程进行采样，捕获其调用栈。

```
Linux 内核 PMU 硬件采样（周期性触发）
    │
    └─ perf_profiler.bpf.c: BPF_PROG_TYPE_PERF_EVENT 程序触发
           ├─ bpf_get_stackid(USER_STACKID_FLAGS)  → 获取用户态调用栈 ID
           ├─ bpf_get_stackid(KERN_STACKID_FLAGS)  → 获取内核态调用栈 ID
           ├─ 记录 {tgid, pid, cpu, stime, u_stack_id, k_stack_id} 到 hash
           └─ 通过 Perf Event Output 上报到用户态
```

#### 5.1.2 双缓冲机制

为实现"持续开启"（Always-On）的性能剖析，采用**双缓冲方案**避免读写冲突：

```
BPF Maps:
  profiler_output_a + stack_map_a  ←→  (交替使用)  ←→  profiler_output_b + stack_map_b

用户态线程控制切换：
  - 读取 buffer_a 进行符号化时，BPF 写入 buffer_b
  - 读取 buffer_b 进行符号化时，BPF 写入 buffer_a
```

用户态通过控制 `state` map 中的标志位，实现无锁的双缓冲切换。

#### 5.1.3 符号化（Symbolization）

用户态 `stringifier.c` 负责将原始栈帧地址转换为可读的函数名：

- **普通进程**：读取 `/proc/<pid>/maps`，结合 ELF 文件的 `.symtab`/`.dynsym` 段，或利用 DWARF 调试信息
- **Java 进程**：通过 `JAVA_ATTACH_TOOL`（attach 到 JVM 的 `-XX:+PreserveFramePointer` 模式）获取 JVM 符号表，输出文件路径为 `/tmp/.deepflow-agent-running-pid`
- **DWARF 展开**：`unwind_tracer.c` 实现了基于 DWARF CFI（Call Frame Information）的精确栈展开，适用于没有帧指针的编译优化代码

#### 5.1.4 栈追踪聚合

用户态通过 `stack_trace_msg_hash`（基于 VPP bihash 的 32-byte key / 8-byte value 哈希表）对采样数据进行聚合统计：

```
Key = {tgid(24bit) | pid(32bit) | cpu(8bit)} + stime + u_stack_id + k_stack_id + e_stack_id
Value = 采样次数（count）
```

采样次数越高，表示该调用路径消耗 CPU 越多，可能存在性能瓶颈。

---

## 6. cBPF/AF_PACKET 采集机制

### 6.1 架构概述

当 eBPF 不可用时（旧内核、Windows 等），Agent 通过 **AF_PACKET**（Linux）或 **WinPcap**（Windows）在网络层抓包，通过 **cBPF 过滤器**（Classic BPF，即传统 pcap 规则）预过滤数据包。

代码位于 `agent/src/dispatcher/recv_engine/af_packet/`。

### 6.2 Dispatcher 工作模式

Agent 支持多种部署场景对应不同的 Dispatcher 模式：

| 模式 | 文件 | 适用场景 |
|------|------|----------|
| `LocalMode` | `local_mode_dispatcher.rs` | 本地进程模式 |
| `AnalyzerMode` | `analyzer_mode_dispatcher.rs` | 分析器模式（流量镜像） |
| `MirrorMode` | `mirror_mode_dispatcher.rs` | 镜像流量处理 |
| `LocalPlusMode` | `local_plus_mode_dispatcher.rs` | 扩展本地模式 |

### 6.3 TPACKET_V3 零拷贝抓包

AF_PACKET 配置使用 **TPACKET_V3**（`tpacket.rs`），实现内核与用户态之间的**共享内存环形缓冲区**：

```
内核驱动收包
    │
    ▼
TPACKET_V3 ring buffer（内核/用户态共享内存）
    │
    ▼
用户态 Dispatcher 直接读取（零拷贝）
    │
    ▼
BPF 过滤（cBPF rules）→ 符合条件的包
    │
    ▼
MetaPacket 封装 → FlowMap 流表处理
```

### 6.4 L4/L7 性能指标计算

在 `flow_generator/perf/` 中，对 TCP/UDP 流进行精确的性能指标计算：

- **TCP**（`tcp.rs`）：RTT、重传率、乱序率、窗口大小变化
- **UDP**（`udp.rs`）：包间隔、丢包估算
- **L7**（通过协议解析器）：请求延迟、错误率（RED 黄金指标）

---

## 7. TLS/SSL 加密流量追踪

### 7.1 OpenSSL Uprobe 方案

对于使用 OpenSSL 的进程，Agent 在 `SSL_read`/`SSL_write` 函数的入口和出口处挂载 uprobe，在**加密之前/解密之后**捕获明文数据。

```
应用进程调用 SSL_write(plaintext)
    │
    ├─ uprobe 触发（SSL_write 入口）
    │    └─ openssl.bpf.c 记录 {pid, fd, buffer_ptr} 到 tls_conn_map
    │
    ├─ 实际加密传输
    │
    └─ uretprobe 触发（SSL_write 出口）
         └─ 从 tls_conn_map 读取入参 → 提取明文 → 关联 TCP fd → 发送
```

**进程发现**：`collect_ssl_uprobe_syms_from_procfs` 启动时遍历 `/proc/` 查找所有加载了 `libssl.so` 的进程，动态注册 uprobe。支持运行期通过 `sched_process_exec` tracepoint 感知新进程的加载。

> **注意**：OpenSSL uprobe 要求内核版本 ≥ 4.17。

### 7.2 BoringSSL / 其他 SSL 库

通过符号搜索机制，支持 `SSL_read`/`SSL_write` 符号名相同的其他 SSL 实现（如 BoringSSL for Chrome/Android）。

---

## 8. Go 语言运行时专项追踪

Go 程序存在两个特殊挑战：
1. Go 有自己的 TLS 实现（`crypto/tls`），不使用 OpenSSL
2. Go 使用 M:N 协程模型，goroutine ID 不等于操作系统线程 ID

### 8.1 Go TLS Uprobe（go_tls.bpf.c）

在 Go 程序的 `crypto/tls.(*Conn).Write` 和 `crypto/tls.(*Conn).Read` 上挂载 uprobe，捕获加密前/解密后的明文数据。

由于 Go 使用**寄存器传参**（Go 1.17+）或**栈传参**（Go 1.16-），Agent 会解析 ELF 文件获取 Go 版本，并据此采用不同的参数读取策略（存储在 `proc_info_map` 中）。

### 8.2 Go HTTP/2 Uprobe（go_http2.bpf.c）

针对 Go 标准库和 `golang.org/x/net/http2` 的 HTTP/2 实现，在以下接口挂载 uprobe：

- `net/http.(*http2serverConn).writeHeaders`
- `net/http.(*http2serverConn).processHeaders`
- `net/http.(*http2clientConnReadLoop).handleResponse`
- `google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader`
- 等

由于在 Go HTTP/2 的读操作 hook 点命中时已读完 buffer，获取的 TCP SEQ 偏移，Agent 通过 `http2_tcp_seq_map`（LRU HASH）保存读操作前后的 SEQ 映射关系，在事后修正。

### 8.3 Go Goroutine 追踪

- `runtime.execute` uprobe：获取当前运行的 goroutine ID
- `runtime.newproc1` 入口/出口 uprobe：捕获父子 goroutine 的创建关系

相关 Maps：
- `goroutines_map`：线程 → 当前协程 ID
- `go_ancerstor_map`（LRU）：子协程 → 父协程 ID
- `pid_tgid_callerid_map`：传递 `runtime.newproc1` 调用参数

### 8.4 偏移量自动推断

不同 Go 版本中结构体（如 `tls.Conn`）的成员偏移不同。Agent 启动时：
1. 扫描 `/proc/` 目录中所有 Go 可执行文件
2. 通过 `bcc_elf_foreach_sym` 解析 ELF 符号表获取 Go 版本
3. 调用 `struct_member_offset_analyze` 分析各关键结构体的成员偏移
4. 将偏移信息写入 `proc_info_map`，供 BPF 程序使用

---

## 9. Wasm 插件机制

### 9.1 架构

Agent 嵌入了一个 **WebAssembly 运行时**（位于 `agent/src/plugin/wasm/`），允许用户编写 Wasm 模块来扩展协议解析能力，无需修改 Agent 本体。

```
cBPF/eBPF 原始数据
    │
    ▼
FlowGenerator 解析器管道
    │ 无法识别的私有协议
    ▼
Wasm Plugin Engine (host.rs)
    ├─ abi_import.rs: 宿主函数导出给 Wasm（读取包数据、写入结果）
    └─ abi_export.rs: 调用 Wasm 模块的入口函数
           └─ 用户实现的协议解析逻辑
                    │ 提取业务流水号 / 协议字段
                    ▼
              AutoTracing 关联 / AutoMetrics 统计
```

### 9.2 插件接口

通过 `WasmPluginApi.proto` 定义了标准接口，Wasm 插件实现后即可：
- 声明自己能处理的协议端口范围
- 解析请求/响应的业务字段（流水号、状态码等）
- 返回结构化的 L7 协议日志

---

## 10. 数据流水线与处理链路

### 10.1 完整数据流

```
                     ┌─────────────────────┐
                     │   Kernel eBPF       │
                     │  (socket_trace.bpf) │
                     └──────────┬──────────┘
                                │ bpf_perf_event_output
                                ▼
                     ┌─────────────────────┐
                     │  Perf Ring Buffer   │
                     │  (per-CPU buffers)  │
                     └──────────┬──────────┘
                                │ perf_reader_poll
                                ▼
                     ┌─────────────────────┐
          perf-reader│  reader_raw_cb()    │
          线程        │  (C libtrace)       │
                     └──────────┬──────────┘
                                │ copy_data_and_enqueue
                         ┌──────┼──────┐
                         ▼      ▼      ▼  (按 socket_id 哈希分发)
                        Q0     Q1    ...Qn   (ring buffer 队列)
                         │      │      │
                   ┌─────┘      └──────┼────────────┐
                   ▼                   ▼             ▼
              Worker-0            Worker-1       Worker-n
                   │
                   │ rust_callback (FFI 回调)
                   ▼
          ┌─────────────────┐
          │  EbpfDispatcher │  (Rust)
          │  ebpf_dispatcher.rs
          └────────┬────────┘
                   │ MetaPacket 封装
                   ▼
          ┌─────────────────┐
          │    FlowMap      │  流表（按五元组聚合）
          │  flow_map.rs    │
          └────────┬────────┘
                   ├─ L4 性能指标（TCP RTT/重传等）
                   ├─ L7 协议解析（HTTP/MySQL/Redis等）
                   │     └─ Wasm Plugin（自定义协议）
                   └─ 生成 AppProtoLogs / Flow / L7Stats
                              │
                              ▼
                   ┌─────────────────┐
                   │   Collector     │  指标聚合 → DeepFlow Server
                   └─────────────────┘
```

### 10.2 多队列并发设计

用户态采用**多工作线程**并行处理 eBPF 数据：

- Perf Reader 线程：从内核 Perf Event Buffer 读取数据，按 `(socket_id % worker_num)` 分发到不同队列
- Worker 线程 N 个：每个 Worker 独占一个 Ring Buffer 队列，串行处理，避免锁竞争
- **Burst 模式**：以 16 条 SockData 为单位批量入队/出队（`MAX_BULK=32`），提升吞吐量
- **Prefetch 优化**：Worker 处理数据时预取后续 3 条 SockData 到 CPU 缓存，减少 Cache Miss

---

## 11. 内核版本兼容性策略

### 11.1 分层兼容方案

Agent 实现了完整的内核版本检测与自适应：

| 内核版本 | 支持能力 |
|----------|----------|
| 2.6+ (cBPF) | AF_PACKET 网络包采集，网络性能指标 |
| 4.1+ | kprobe/kretprobe，基础 eBPF |
| 4.7+ | tracepoint 类型 eBPF 程序 |
| 4.9+ | perf event 类型 eBPF，On-CPU 性能剖析 |
| 4.14+ | NUMA-aware map 分配，完整 Socket 追踪 |
| 4.17+ | OpenSSL uprobe（支持更完整的 uprobe 特性） |
| 5.2+ | 协议推断快速缓存（`__proto_infer_cache_map`），超过 4096 指令 |
| 5.5+ | fentry/fexit BPF trampoline（最低探针开销） |

特殊兼容：
- **RHEL/CentOS 7（内核 3.10）**：Red Hat 将 eBPF 特性 backport 到 3.10.0-940+，Agent 特别支持此版本
- **麒麟（K_TYPE_KYLIN）**：国产操作系统特殊内核类型检测

### 11.2 BTF 与结构体偏移推断

为适配不同内核版本中结构体成员的布局变化（如 `task_struct`、`sock` 等），Agent 采用两种方式：

1. **BTF（BPF Type Format）**：在支持 BTF 的内核上，从 `/sys/kernel/btf/vmlinux` 或离线 BTF 文件中直接读取结构体成员偏移，写入 `__members_offset` map
2. **运行时推断**：在不支持 BTF 的内核上，Agent 在用户态启动一个辅助服务器/客户端（`OFFSET_INFER_SERVER_ADDR:54583`），通过实际网络通信来推断 `struct sock` 等关键内核结构体的成员偏移

---

## 12. 性能与资源管理

### 12.1 内存管理

- **自定义内存分配器**：使用 DPDK 风格的 `mem.c` 进行大块内存预分配，减少 malloc/free 碎片
- **对象池**：`pool.rs` 实现流表节点的内存池复用，避免频繁堆分配
- **MemoryPool**：用于 MetaPacket 的批量分配（`BatchedBox`）

### 12.2 Map 资源回收

eBPF Hash Map 容量有限，Agent 实现了老化回收机制：

- `__socket_info_map` 和 `__trace_map` 达到 `socket_map_max_reclaim` 阈值时触发清理
- 通过 `__trace_stats_map`（PERCPU_ARRAY）持续监控各 Map 的使用率
- `kern_socket_map_max/used` 和 `kern_trace_map_max/used` 统计供用户态监控

### 12.3 数据限流

- `data_limit_max`：单次捕获的最大数据长度（默认 16KB，`CAP_LEN_MAX=16384`）
- `set_protocol_ports_bitmap`：通过端口位图精细控制哪些端口的流量需要深度解析
- 协议过滤器（`__protocol_filter`）：可按协议类型关闭解析，降低 CPU 开销

### 12.4 可观测性

Agent 内置了完整的自监控统计，通过 `socket_trace_stats` 接口暴露：

```
eBPF 统计：
  perf_pages_cnt       - Perf Buffer 占用页数
  kern_lost            - 因 Perf Buffer 满导致的数据丢失数
  kern_socket_map_used - Socket 追踪 Hash 表当前使用量

数据处理统计：
  user_enqueue_count   - 用户态收到的 SockData 总数
  user_dequeue_count   - 工作线程处理的 SockData 总数
  user_enqueue_lost    - 因队列满丢失的数据量
  queue_burst_count    - Burst 操作次数

网络包统计：
  rx_packets/tx_packets - 收发包数
  rx_bytes/tx_bytes     - 收发字节数
  dropped_packets       - 丢包数
```

---

## 小结

DeepFlow Agent 的核心设计哲学是**零侵入、全栈、自适应**。通过将 eBPF 内核态程序（C/BPF）、用户态管理库（C）与主体逻辑（Rust）有机结合，实现了：

- **零侵入**：无需修改业务代码，通过系统调用层面的 eBPF 探针实现全量数据采集
- **全栈覆盖**：从网络层（cBPF/AF_PACKET）到应用层（L7 协议解析），从 CPU 性能（On-CPU Profiling）到分布式调用链（AutoTracing），一套 Agent 覆盖所有可观测性需求
- **自适应内核**：自动检测内核版本和特性，在 kprobe/tracepoint/fentry 之间自动选择最优探针类型，通过 BTF/运行时推断解决跨版本结构体兼容问题
- **高性能**：多队列并发、Burst 批处理、CPU Prefetch、自定义内存管理，确保在高流量场景下的处理性能
