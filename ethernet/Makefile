# Ethernet Data Link Layer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -I$(COMMON_INC_DIR) -g

SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

COMMON_DIR = ../common
COMMON_INC_DIR = $(COMMON_DIR)/include

# Library source files
LIB_SRCS = $(SRC_DIR)/crc32.c $(SRC_DIR)/ethernet_send.c $(SRC_DIR)/ethernet_recv.c
LIB_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_SRCS))

.PHONY: all clean

all: $(LIB_OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
