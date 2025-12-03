# ARP Protocol Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(ETHERNET_INC_DIR) -I$(COMMON_INC_DIR) -g
LDFLAGS = -lm -lpcap

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

# Ethernet layer directories
ETHERNET_DIR = ../ethernet
ETHERNET_SRC_DIR = $(ETHERNET_DIR)/src
ETHERNET_INC_DIR = $(ETHERNET_DIR)/include

# Source files
ARP_COMMON_SRCS = $(SRC_DIR)/arp.c
SEND_SRCS = $(ARP_COMMON_SRCS) $(SRC_DIR)/arp_send.c $(SRC_DIR)/send_main.c
RECV_SRCS = $(ARP_COMMON_SRCS) $(SRC_DIR)/arp_send.c $(SRC_DIR)/arp_recv.c $(SRC_DIR)/recv_main.c

# Ethernet layer source files
ETHERNET_COMMON_SRCS = $(ETHERNET_SRC_DIR)/crc32.c
ETHERNET_SEND_SRCS = $(ETHERNET_COMMON_SRCS) $(ETHERNET_SRC_DIR)/ethernet_send.c
ETHERNET_RECV_SRCS = $(ETHERNET_COMMON_SRCS) $(ETHERNET_SRC_DIR)/ethernet_recv.c $(ETHERNET_SRC_DIR)/ethernet_send.c

# Object files
SEND_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SEND_SRCS))
RECV_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(RECV_SRCS))

# Ethernet layer object files
ETHERNET_SEND_OBJS = $(patsubst $(ETHERNET_SRC_DIR)/%.c,$(BUILD_DIR)/eth_%.o,$(ETHERNET_SEND_SRCS))
ETHERNET_RECV_OBJS = $(patsubst $(ETHERNET_SRC_DIR)/%.c,$(BUILD_DIR)/eth_%.o,$(ETHERNET_RECV_SRCS))

# Executables
SEND_TARGET = arp_send
RECV_TARGET = arp_recv

.PHONY: all clean send recv dirs

all: dirs $(SEND_TARGET) $(RECV_TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(DATA_DIR) $(OUTPUT_DIR)

$(SEND_TARGET): $(SEND_OBJS) $(ETHERNET_SEND_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(RECV_TARGET): $(RECV_OBJS) $(ETHERNET_SEND_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/eth_%.o: $(ETHERNET_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(SEND_TARGET) $(RECV_TARGET)

send: dirs $(SEND_TARGET)
	@echo "Built $(SEND_TARGET)"

recv: dirs $(RECV_TARGET)
	@echo "Built $(RECV_TARGET)"
