# 网络协议栈实现

用户空间 C 语言网络协议栈 (Ethernet + ARP + IPv4)。

## 依赖

```bash
sudo apt-get install libpcap-dev
```

## 编译

```bash
make
```

## 运行

```bash
# 终端 1 - 接收
cd ip && sudo ./ip_recv

# 终端 2 - 发送
cd ip && sudo ./ip_send
```

## 日志系统

日志文件位于 `ip/output/` 目录。

控制终端日志输出：
```bash
# 正常运行（终端 + 文件）
sudo ./ip_recv

# 静默模式（仅文件）
sudo LOG_QUIET=1 ./ip_recv
```

## 清理

```bash
make clean
```
