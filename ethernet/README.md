# 以太网数据链路层

使用 libpcap 在真实网卡上收发以太网数据帧。

## 实现功能

### 发送方
1. 获取并显示网络接口列表
2. 用户输入目标 MAC 地址
3. 选择网卡并自动获取该网卡的 MAC 地址作为源地址
4. 封装数据帧：目的MAC + 源MAC + 类型 + 数据 + CRC32
5. 通过 libpcap 发送到网卡

### 接收方
1. 获取并显示网络接口列表
2. 选择网卡并自动获取该网卡的 MAC 地址
3. 设置 BPF 过滤器（只接收发往本地 MAC 或广播地址的帧）
4. 捕获数据包并验证（CRC、MAC、大小）
5. 提取数据并保存

## 帧结构

```
+------------------+------------------+----------+--------------+--------+
| 目的MAC (6字节)  | 源MAC (6字节)    | 类型(2)  | 数据(46-1500)| CRC(4) |
+------------------+------------------+----------+--------------+--------+
```

- 最小帧长：64 字节
- 最大帧长：1518 字节
- CRC 算法：CRC-32 (0xEDB88320)

## 编译

```bash
make          # 编译发送和接收程序
make send     # 只编译发送程序
make recv     # 只编译接收程序
make clean    # 清理编译文件
```

## 使用方法

### 发送数据

```bash
# 准备输入数据（46-1500 字节）
echo "Test data for Ethernet transmission..." > data/input.txt

# 运行发送程序（需要 root 权限）
sudo ./ethernet_send [input_file]

# 使用默认参数
sudo ./ethernet_send
# 默认输入: data/input.txt
```

程序会：
1. 列出所有网络接口
2. 提示输入目标 MAC 地址（格式：AA:BB:CC:DD:EE:FF）
3. 选择发送接口后，自动获取该接口的 MAC 地址作为源地址
4. 发送数据帧

### 接收数据

```bash
# 运行接收程序（需要 root 权限）
sudo ./ethernet_recv [output_file]

# 使用默认参数
sudo ./ethernet_recv
# 默认输出: output/received_data.txt
```

程序会：
1. 列出所有网络接口
2. 选择接收接口后，自动获取该接口的 MAC 地址
3. 使用该 MAC 地址设置 BPF 过滤器
4. 开始监听并捕获数据帧

**建议：** 使用 `lo`（本地环回）接口测试，流量较少且稳定。

### 完整测试流程

**终端 1（接收方）:**
```bash
cd ethernet
sudo ./ethernet_recv
# 选择接口（建议选 lo 本地环回）
# 程序会自动显示该接口的 MAC 地址并开始监听
```

**终端 2（发送方）:**
```bash
cd ethernet
sudo ./ethernet_send
# 输入目标 MAC 地址（使用接收方显示的 MAC 地址）
# 选择相同接口
# 程序会自动获取源 MAC 并发送
```

接收方会显示捕获到的帧信息，数据保存在 `output/received_data.txt`。

### 验证数据完整性

```bash
diff data/input.txt output/received_data.txt
# 无输出表示数据完全一致
```

## 配置说明

### MAC 地址

**MAC 地址自动获取：**
- 发送方：选择网卡后自动获取该网卡的 MAC 作为源地址，目标 MAC 由用户输入
- 接收方：选择网卡后自动获取该网卡的 MAC 作为本地地址

**如何查看网卡 MAC 地址：**
```bash
ip link show          # Linux
ifconfig             # 通用方法
```

MAC 地址通过 `ioctl()` 系统调用和 `SIOCGIFHWADDR` 命令从网卡获取。

### 以太网类型

修改 `src/send_main.c`:
```c
uint16_t eth_type = ETHERNET_TYPE_IPV4;  // 0x0800
```

可选类型（定义在 `include/ethernet.h`）:
- `ETHERNET_TYPE_IPV4` (0x0800)
- `ETHERNET_TYPE_ARP` (0x0806)
- `ETHERNET_TYPE_IPV6` (0x86DD)

### 过滤器

接收方自动根据所选网卡的 MAC 地址设置 BPF 过滤器：
```
ether dst <网卡MAC地址> or ether broadcast
```

只捕获发往本地 MAC 或广播地址的帧，过滤掉无关流量。

### 捕获数量

修改 `src/ethernet_recv.c` 中的捕获数量：
```c
pcap_loop(handle, 10, packet_handler, NULL);  // 捕获10个包
```

## 数据约束

- 输入数据大小：46-1500 字节
- 小于 46 字节：自动填充 0
- 大于 1500 字节：拒绝发送
- 帧总大小：64-1518 字节

