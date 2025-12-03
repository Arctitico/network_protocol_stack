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

## 清理

```bash
make clean
```
