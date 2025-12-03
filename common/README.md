# Common Utilities

共享的工具模块，提供跨层的通用功能。

## 模块

### Logger (日志系统)

统一的日志系统，支持：
- 四个日志级别：`DEBUG`、`INFO`、`WARN`、`ERROR`
- 输出到文件和/或终端
- 彩色终端输出
- 十六进制数据转储
- 时间戳记录

## 编译

```bash
make          # 编译静态库
make clean    # 清理编译文件
```

## 使用示例

```c
#include "logger.h"

logger_t logger;

// 初始化日志器
logger_init(&logger, "MY_MODULE", "output/my_module.log", LOG_LEVEL_DEBUG, 1);

// 写日志
LOG_INFO(&logger, "Started with %d items", count);
LOG_DEBUG(&logger, "Processing item: %s", name);
LOG_WARN(&logger, "Resource low: %d%%", percent);
LOG_ERROR(&logger, "Failed to open file: %s", filename);

// 十六进制转储
logger_hex_dump(&logger, LOG_LEVEL_DEBUG, "Packet data", buffer, len);

// 关闭
logger_close(&logger);
```
