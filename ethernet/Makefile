# Ethernet Data Link Layer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(COMMON_INC_DIR) -g
LDFLAGS = -lpcap

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
DATA_DIR = data
OUTPUT_DIR = output

# Common library
COMMON_DIR = ../common
COMMON_INC_DIR = $(COMMON_DIR)/include
COMMON_LIB = $(COMMON_DIR)/build/libcommon.a

# Source files
LOCAL_COMMON_SRCS = $(SRC_DIR)/crc32.c
SEND_SRCS = $(LOCAL_COMMON_SRCS) $(SRC_DIR)/ethernet_send.c $(SRC_DIR)/send_main.c
RECV_SRCS = $(LOCAL_COMMON_SRCS) $(SRC_DIR)/ethernet_send.c $(SRC_DIR)/ethernet_recv.c $(SRC_DIR)/recv_main.c

# Object files
SEND_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SEND_SRCS))
RECV_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(RECV_SRCS))

# Executables
SEND_TARGET = ethernet_send
RECV_TARGET = ethernet_recv

.PHONY: all clean send recv dirs

all: dirs $(SEND_TARGET) $(RECV_TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(DATA_DIR) $(OUTPUT_DIR)

$(SEND_TARGET): $(SEND_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(RECV_TARGET): $(RECV_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(SEND_TARGET) $(RECV_TARGET)


