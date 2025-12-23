# WEB

HTTP/1.0 浏览器和服务器。**不依赖本项目协议栈，直接使用系统 Socket API。**

## 编译

```bash
sudo apt-get install libgtk-3-dev libwebkit2gtk-4.0-dev  # 依赖
make clean && make 
```

## 运行

```bash
cd data && ../tiny_server 9998   # 启动服务器
```
```bash
./browser                         # 启动浏览器
```

测试：`http://localhost:9998/index.html` 或 `http://localhost:9998/cgi-bin/adder?100&200`
