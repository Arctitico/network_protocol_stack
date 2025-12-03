# ARP Protocol Implementation

ARP (Address Resolution Protocol) 实现，用于将 IP 地址解析为 MAC 地址。

## 编译

```bash
make          # 编译发送端和接收端
make clean    # 清理编译文件
```

## 使用方法 (独立测试)

**注意：** 这些工具仅用于单独测试 ARP 层。如果要运行完整的网络栈，请使用 `ip/` 目录下的工具（`ip_send` 会自动进行 ARP 解析）。

### 接收端 (ARP Reply/Request Listener)
监听网络上的 ARP 请求和响应。

```bash
sudo ./arp_recv
```

### 发送端 (ARP Request)
发送 ARP 请求以解析目标 IP 的 MAC 地址。

```bash
sudo ./arp_send -t <目标IP>
# 示例: sudo ./arp_send -t 192.168.1.200
```

程序会自动检测所选接口的本地 IP 和子网掩码。
