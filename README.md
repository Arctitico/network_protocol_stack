# 网络协议栈实现

这是一个在用户空间实现的 C 语言网络协议栈，目前包含以太网（数据链路层）、ARP（地址解析协议）和 IPv4（网络层）。

## 项目结构

- `common/`: 共享工具库 (日志系统等)
- `ethernet/`: 数据链路层 (基于 libpcap)
- `arp/`: 地址解析协议 (ARP)
- `ip/`: 网络层 (IPv4, 分片/重组)

## 前置要求

- Linux 环境
- GCC 编译器
- GNU Make
- libpcap 开发头文件 (`sudo apt-get install libpcap-dev`)

## 快速开始

### 1. 编译所有内容
```bash
make
```

### 2. 运行协议栈

**终端 1 (接收端):**
```bash
cd ip
sudo ./ip_recv
# 选择一个网络接口 (例如 'lo' 用于本地测试)
# 记下显示的本地 IP 地址
```

**终端 2 (发送端):**
```bash
cd ip
sudo ./ip_send
# 选择相同的网络接口
# 输入目标 IP 地址 (从终端 1 获取)
```

## 日志系统

本项目使用集中式日志系统，每个协议层都有对应的日志文件。

### 日志文件位置

- `ip/output/` 

### 控制终端输出

默认情况下，日志同时输出到文件和终端。可以通过 `LOG_QUIET` 环境变量禁用终端输出：

```bash
# 正常运行（终端 + 文件）
sudo ./ip_recv

# 静默模式（仅保存到文件，不输出到终端）
sudo LOG_QUIET=1 ./ip_recv
```

## 清理
```bash
make clean
```
