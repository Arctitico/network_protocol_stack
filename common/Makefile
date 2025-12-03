# Common Utilities Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -g
AR = ar
ARFLAGS = rcs

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Static library
TARGET = $(BUILD_DIR)/libcommon.a

.PHONY: all clean dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Common Utilities Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all   - Build static library (default)"
	@echo "  clean - Remove build files"
