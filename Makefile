# Root Makefile

.PHONY: all clean common ethernet arp ip help

# Default target
all: common ethernet arp ip

# Build common utilities
common:
	@echo "Building Common Utilities..."
	@$(MAKE) -C common all

# Build Ethernet layer
ethernet: common
	@echo "Building Ethernet Layer..."
	@$(MAKE) -C ethernet all

# Build ARP layer
arp: common
	@echo "Building ARP Layer..."
	@$(MAKE) -C arp all

# Build IP layer
ip: common
	@echo "Building IP Layer..."
	@$(MAKE) -C ip all

# Clean all layers
clean:
	@echo "Cleaning all layers..."
	@$(MAKE) -C common clean
	@$(MAKE) -C ethernet clean
	@$(MAKE) -C arp clean
	@$(MAKE) -C ip clean
	@echo "All layers cleaned"

# Help
help:
	@echo "Available targets:"
	@echo "  make          - Build all layers"
	@echo "  make clean    - Clean all layers"
	@echo "  make common   - Build common utilities only"
	@echo "  make ethernet - Build Ethernet layer only"
	@echo "  make arp      - Build ARP layer only"
	@echo "  make ip       - Build IP layer only"
