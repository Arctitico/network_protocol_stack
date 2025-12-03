# Root Makefile

.PHONY: all clean ethernet ip help

# Default target
all: ethernet ip

# Build Ethernet layer
ethernet:
	@echo "Building Ethernet Layer..."
	@$(MAKE) -C ethernet all

# Build IP layer
ip:
	@echo "Building IP Layer..."
	@$(MAKE) -C ip all

# Clean all layers
clean:
	@echo "Cleaning all layers..."
	@$(MAKE) -C ethernet clean
	@$(MAKE) -C ip clean
	@echo "All layers cleaned"

# Help
help:
	@echo "Available targets:"
	@echo "  make          - Build all layers"
	@echo "  make clean    - Clean all layers"
	@echo "  make ethernet - Build Ethernet layer only"
	@echo "  make ip       - Build IP layer only"
