# 以太网数据链路层

使用 `libpcap` 实现的以太网数据链路层，用于原始数据包的访问。

## 编译

```bash
make          # 编译发送端和接收端
make clean    # 清理编译文件
```

## 使用方法 (独立测试)

**注意：** 这些工具仅用于单独测试以太网层。如果要运行完整的网络栈，请使用 `ip/` 目录下的工具。

### 接收端
捕获 **10 个数据包** 后退出。

```bash
sudo ./ethernet_recv [输出文件]
# 默认输出: output/received_data.txt
```

### 发送端
发送单个以太网帧。

```bash
sudo ./ethernet_send [输入文件]
# 默认输入: data/input.txt
```
