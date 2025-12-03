# Root Makefile

.PHONY: all clean ethernet arp ip help

# Default target
all: ethernet arp ip

# Build Ethernet layer
ethernet:
	@echo "Building Ethernet Layer..."
	@$(MAKE) -C ethernet all

# Build ARP layer
arp:
	@echo "Building ARP Layer..."
	@$(MAKE) -C arp all

# Build IP layer
ip:
	@echo "Building IP Layer..."
	@$(MAKE) -C ip all

# Clean all layers
clean:
	@echo "Cleaning all layers..."
	@$(MAKE) -C ethernet clean
	@$(MAKE) -C arp clean
	@$(MAKE) -C ip clean
	@echo "All layers cleaned"

# Help
help:
	@echo "Available targets:"
	@echo "  make          - Build all layers"
	@echo "  make clean    - Clean all layers"
	@echo "  make ethernet - Build Ethernet layer only"
	@echo "  make arp      - Build ARP layer only"
	@echo "  make ip       - Build IP layer only"
