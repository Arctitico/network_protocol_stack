# IP Network Layer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(ETHERNET_INC_DIR) -I$(ARP_INC_DIR) -I$(COMMON_INC_DIR) -g
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

# ARP layer directories
ARP_DIR = ../arp
ARP_SRC_DIR = $(ARP_DIR)/src
ARP_INC_DIR = $(ARP_DIR)/include

# Source files
SEND_SRCS = $(SRC_DIR)/ip_send.c $(SRC_DIR)/send_main.c
RECV_SRCS = $(SRC_DIR)/ip_recv.c $(SRC_DIR)/recv_main.c

# Ethernet layer source files
ETHERNET_COMMON_SRCS = $(ETHERNET_SRC_DIR)/crc32.c
ETHERNET_SEND_SRCS = $(ETHERNET_COMMON_SRCS) $(ETHERNET_SRC_DIR)/ethernet_send.c
ETHERNET_RECV_SRCS = $(ETHERNET_COMMON_SRCS) $(ETHERNET_SRC_DIR)/ethernet_recv.c $(ETHERNET_SRC_DIR)/ethernet_send.c

# ARP layer source files
ARP_SRCS = $(ARP_SRC_DIR)/arp.c $(ARP_SRC_DIR)/arp_send.c
ARP_RECV_SRCS = $(ARP_SRC_DIR)/arp.c $(ARP_SRC_DIR)/arp_send.c $(ARP_SRC_DIR)/arp_recv.c

# Object files
SEND_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SEND_SRCS))
RECV_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(RECV_SRCS))

# Ethernet layer object files
ETHERNET_SEND_OBJS = $(patsubst $(ETHERNET_SRC_DIR)/%.c,$(BUILD_DIR)/eth_%.o,$(ETHERNET_SEND_SRCS))
ETHERNET_RECV_OBJS = $(patsubst $(ETHERNET_SRC_DIR)/%.c,$(BUILD_DIR)/eth_%.o,$(ETHERNET_RECV_SRCS))

# ARP layer object files
ARP_OBJS = $(patsubst $(ARP_SRC_DIR)/%.c,$(BUILD_DIR)/arp_%.o,$(ARP_SRCS))
ARP_RECV_OBJS = $(patsubst $(ARP_SRC_DIR)/%.c,$(BUILD_DIR)/arp_%.o,$(ARP_RECV_SRCS))

# Executables
SEND_TARGET = ip_send
RECV_TARGET = ip_recv

.PHONY: all clean send recv dirs

all: dirs $(SEND_TARGET) $(RECV_TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(DATA_DIR) $(OUTPUT_DIR)

$(SEND_TARGET): $(SEND_OBJS) $(ETHERNET_SEND_OBJS) $(ARP_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(RECV_TARGET): $(RECV_OBJS) $(BUILD_DIR)/ip_send.o $(ETHERNET_RECV_OBJS) $(ARP_RECV_OBJS) $(ETHERNET_SEND_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/eth_%.o: $(ETHERNET_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/arp_%.o: $(ARP_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(SEND_TARGET) $(RECV_TARGET)
