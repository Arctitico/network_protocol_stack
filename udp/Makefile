# UDP Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(IP_INC_DIR) -I$(ICMP_INC_DIR) -I$(ARP_INC_DIR) -I$(ETHERNET_INC_DIR) -I$(COMMON_INC_DIR) -g
LDFLAGS = -lm -lpcap -lpthread

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

# IP layer directories
IP_DIR = ../ip
IP_SRC_DIR = $(IP_DIR)/src
IP_INC_DIR = $(IP_DIR)/include

# ICMP layer directories
ICMP_DIR = ../icmp
ICMP_SRC_DIR = $(ICMP_DIR)/src
ICMP_INC_DIR = $(ICMP_DIR)/include

# Ethernet layer directories
ETHERNET_DIR = ../ethernet
ETHERNET_SRC_DIR = $(ETHERNET_DIR)/src
ETHERNET_INC_DIR = $(ETHERNET_DIR)/include

# ARP layer directories
ARP_DIR = ../arp
ARP_SRC_DIR = $(ARP_DIR)/src
ARP_INC_DIR = $(ARP_DIR)/include

# UDP source files
UDP_LIB_SRCS = $(SRC_DIR)/udp.c $(SRC_DIR)/udp_send.c $(SRC_DIR)/udp_recv.c
SERVER_SRCS = $(SRC_DIR)/server_main.c
CLIENT_SRCS = $(SRC_DIR)/client_main.c

# Lower layer source files
IP_SRCS = $(IP_SRC_DIR)/ip_send.c $(IP_SRC_DIR)/ip_recv.c
ICMP_SRCS = $(ICMP_SRC_DIR)/icmp_recv.c
ETHERNET_SRCS = $(ETHERNET_SRC_DIR)/crc32.c $(ETHERNET_SRC_DIR)/ethernet_send.c $(ETHERNET_SRC_DIR)/ethernet_recv.c
ARP_SRCS = $(ARP_SRC_DIR)/arp.c $(ARP_SRC_DIR)/arp_send.c $(ARP_SRC_DIR)/arp_recv.c

# UDP object files
UDP_LIB_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(UDP_LIB_SRCS))
SERVER_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SERVER_SRCS))
CLIENT_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CLIENT_SRCS))

# Lower layer object files
IP_OBJS = $(patsubst $(IP_SRC_DIR)/%.c,$(BUILD_DIR)/ip_%.o,$(IP_SRCS))
ICMP_OBJS = $(patsubst $(ICMP_SRC_DIR)/%.c,$(BUILD_DIR)/icmp_%.o,$(ICMP_SRCS))
ETHERNET_OBJS = $(patsubst $(ETHERNET_SRC_DIR)/%.c,$(BUILD_DIR)/eth_%.o,$(ETHERNET_SRCS))
ARP_OBJS = $(patsubst $(ARP_SRC_DIR)/%.c,$(BUILD_DIR)/arp_%.o,$(ARP_SRCS))

# All lower layer objects
LOWER_LAYER_OBJS = $(IP_OBJS) $(ICMP_OBJS) $(ETHERNET_OBJS) $(ARP_OBJS)

# Executables
SERVER_TARGET = udp_server
CLIENT_TARGET = udp_client

.PHONY: all clean dirs

all: dirs $(SERVER_TARGET) $(CLIENT_TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(DATA_DIR) $(OUTPUT_DIR)

$(SERVER_TARGET): $(SERVER_OBJS) $(UDP_LIB_OBJS) $(LOWER_LAYER_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_OBJS) $(UDP_LIB_OBJS) $(LOWER_LAYER_OBJS) $(COMMON_LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ip_%.o: $(IP_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/icmp_%.o: $(ICMP_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/eth_%.o: $(ETHERNET_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/arp_%.o: $(ARP_SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(SERVER_TARGET) $(CLIENT_TARGET)
