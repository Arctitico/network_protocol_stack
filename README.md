# 网络协议栈实现

用户空间 C 语言网络协议栈 (Ethernet + ARP + IPv4 + ICMP + UDP)。

## 依赖

```bash
sudo apt-get install libpcap-dev
```

## 编译

```bash
make
```

## 运行

本项目实现了 UDP 协议栈，包含服务器和客户端测试程序。

```bash
# 终端 1 - 启动 UDP 服务器
cd udp && sudo ./udp_server [port]

# 终端 2 - 启动 UDP 客户端发送数据
cd udp && sudo ./udp_client [data_file] [port]
```

例如：
```bash
# 终端 1
cd udp && sudo ./udp_server 5050

# 终端 2
cd udp && sudo ./udp_client data/input.txt 5050
```

## 日志系统

日志文件位于 `udp/output/` 目录。

### 环境变量控制

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LOG_DISABLE` | 0 | 设为 1 禁用所有日志文件记录 |
| `LOG_QUIET` | 1 | 设为 0 启用控制台详细日志输出 |

### 使用示例

```bash
# 默认模式：记录日志文件，控制台静默
sudo ./udp_server 5050

# 禁用日志文件记录
sudo LOG_DISABLE=1 ./udp_server 5050

# 启用控制台详细日志
sudo LOG_QUIET=0 ./udp_server 5050

# 禁用所有日志
sudo LOG_DISABLE=1 LOG_QUIET=1 ./udp_server 5050
```

## 清理

```bash
make clean
```
