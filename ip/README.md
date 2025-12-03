# IP 网络层

IPv4 网络层的实现，支持分片、重组，并集成 ARP 协议进行地址解析。

## 编译

```bash
make          # 编译发送端和接收端
make clean    # 清理编译文件
```

## 使用方法 (全栈模式)

### 接收端
无限运行，通过以太网层捕获数据包。

```bash
sudo ./ip_recv [输出文件]
# 默认输出: output/received_data.txt
```

### 发送端
从文件读取数据并作为 IP 数据包发送。会自动使用 ARP 解析目标 MAC 地址。

```bash
sudo ./ip_send [输入文件] [协议号]
# 默认输入: data/input.txt
# 默认协议: 6 (TCP)
```

## 示例流程

1.  **启动接收端:**
    ```bash
    sudo ./ip_recv
    ```
    选择网络接口 (例如 `lo` 或 `eth0`)。程序会自动检测并显示本地 IP。

2.  **启动发送端:**
    ```bash
    sudo ./ip_send
    ```
    *   选择与接收端相同的网络接口。
    *   输入 **目标 IP 地址** (接收端显示的 IP)。
    *   程序将自动发送 ARP 请求获取目标 MAC，然后发送 IP 数据包。

