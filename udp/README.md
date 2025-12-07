# UDP 传输层

UDP 协议实现，提供无连接的数据报通信服务。

## 功能

实现了 UDP 协议的五个核心函数：

- `udp_socket()` - 创建 UDP 套接字
- `udp_bind()` - 绑定本地地址和端口
- `udp_sendto()` - 发送 UDP 数据报
- `udp_recvfrom()` - 接收 UDP 数据报
- `udp_closesocket()` - 关闭套接字

## 编译

```bash
make
```

