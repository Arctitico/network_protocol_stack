# IP Network Layer Makefile (Library Only)

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(ETHERNET_INC_DIR) -I$(ARP_INC_DIR) -I$(ICMP_INC_DIR) -I$(UDP_INC_DIR) -I$(COMMON_INC_DIR) -g

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
DATA_DIR = data
OUTPUT_DIR = output

# Common library
COMMON_DIR = ../common
COMMON_INC_DIR = $(COMMON_DIR)/include

# Ethernet layer directories
ETHERNET_DIR = ../ethernet
ETHERNET_INC_DIR = $(ETHERNET_DIR)/include

# ARP layer directories
ARP_DIR = ../arp
ARP_INC_DIR = $(ARP_DIR)/include

# ICMP layer directories
ICMP_DIR = ../icmp
ICMP_INC_DIR = $(ICMP_DIR)/include

# UDP layer directories
UDP_DIR = ../udp
UDP_INC_DIR = $(UDP_DIR)/include

# Source files (library only)
IP_SRCS = $(SRC_DIR)/ip_send.c $(SRC_DIR)/ip_recv.c

# Object files
IP_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(IP_SRCS))

# Library target
LIB_TARGET = $(BUILD_DIR)/libip.a

.PHONY: all clean dirs

all: dirs $(LIB_TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(DATA_DIR) $(OUTPUT_DIR)

$(LIB_TARGET): $(IP_OBJS)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(LIB_TARGET)
