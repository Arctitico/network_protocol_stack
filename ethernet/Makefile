# Ethernet Data Link Layer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -I$(INC_DIR) -g
LDFLAGS = -lpcap

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
DATA_DIR = data
OUTPUT_DIR = output

# Source files
COMMON_SRCS = $(SRC_DIR)/crc32.c
SEND_SRCS = $(COMMON_SRCS) $(SRC_DIR)/ethernet_send.c $(SRC_DIR)/send_main.c
RECV_SRCS = $(COMMON_SRCS) $(SRC_DIR)/ethernet_recv.c $(SRC_DIR)/recv_main.c

# Object files
SEND_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SEND_SRCS))
RECV_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(RECV_SRCS))

# Executables
SEND_TARGET = ethernet_send
RECV_TARGET = ethernet_recv

.PHONY: all clean send recv test dirs

all: dirs $(SEND_TARGET) $(RECV_TARGET)

# Create necessary directories
dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(DATA_DIR)
	@mkdir -p $(OUTPUT_DIR)

# Build sender
$(SEND_TARGET): $(SEND_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Built sender: $(SEND_TARGET)"

# Build receiver
$(RECV_TARGET): $(RECV_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "Built receiver: $(RECV_TARGET)"

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Shortcuts
send: dirs $(SEND_TARGET)

recv: dirs $(RECV_TARGET)

# Test targets
test: all
	@echo "Running Ethernet layer test..."
	@echo "Step 1: Sending frame..."
	./$(SEND_TARGET)
	@echo ""
	@echo "Step 2: Receiving frame..."
	./$(RECV_TARGET)
	@echo ""
	@echo "Test completed!"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SEND_TARGET) $(RECV_TARGET)
	rm -f $(DATA_DIR)/frame.bin
	rm -f $(OUTPUT_DIR)/received_data.txt
	@echo "Cleaned build artifacts"

# Clean everything including data
cleanall: clean
	rm -rf $(DATA_DIR)/*.txt $(DATA_DIR)/*.bin
	rm -rf $(OUTPUT_DIR)/*
	@echo "Cleaned all generated files"

# Help
help:
	@echo "Ethernet Data Link Layer Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build both sender and receiver (default)"
	@echo "  send     - Build sender only"
	@echo "  recv     - Build receiver only"
	@echo "  test     - Build and run a complete send/receive test"
	@echo "  clean    - Remove build artifacts and executables"
	@echo "  cleanall - Remove all generated files including data"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build everything"
	@echo "  make test         # Run complete test"
	@echo "  make clean        # Clean build files"
