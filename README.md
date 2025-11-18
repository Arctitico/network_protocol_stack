## 当前实现状态

- 数据链路层（以太网）: 已完成
- 网络层: 未实现
- 传输层: 未实现
- 应用层: 未实现

详细使用说明见 `ethernet/README.md`

## 环境要求

- Linux/WSL (Ubuntu)
- GCC 编译器
- libpcap 开发库
- root 权限（访问网卡）

## 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev
```

## 项目结构

```
C_NETWORK/
├── Makefile                    # 根目录构建文件
├── README.md                   # 本文档
├── ethernet/                   # 数据链路层实现
│   ├── Makefile
│   ├── README.md              # 数据链路层说明
│   ├── include/               # 头文件
│   ├── src/                   # 源代码
│   ├── data/                  # 输入数据和帧文件
│   ├── output/                # 输出数据（交付给上层）
│   └── build/                 # 编译生成的目标文件
└── reference/                  # 参考资料
```

## 编译

```bash
# 编译所有层
make

# 或单独编译数据链路层
cd ethernet
make
```

## 清理

```bash
# 清理构建文件
make clean

# 清理所有生成文件（包括数据）
cd ethernet
make cleanall
```


