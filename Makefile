# Industrial Ethernet Protocol Stack - Root Makefile

.PHONY: all clean ethernet test help

# Default target
all: ethernet

# Build Ethernet layer
ethernet:
	@echo "Building Ethernet Data Link Layer..."
	@$(MAKE) -C ethernet all
	@echo ""

# Test Ethernet layer
test-ethernet:
	@echo "Testing Ethernet Data Link Layer..."
	@$(MAKE) -C ethernet test
	@echo ""

# Run all tests
test: test-ethernet

# Clean all layers
clean:
	@echo "Cleaning all layers..."
	@$(MAKE) -C ethernet clean
	@echo "All layers cleaned"

# Clean everything including data
cleanall:
	@echo "Cleaning all layers and data..."
	@$(MAKE) -C ethernet cleanall
	@echo "Everything cleaned"

# Help
help:
	@echo "Industrial Ethernet Protocol Stack - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all           - Build all protocol layers (default)"
	@echo "  ethernet      - Build Ethernet data link layer only"
	@echo "  test          - Run tests for all layers"
	@echo "  test-ethernet - Run Ethernet layer test only"
	@echo "  clean         - Clean build artifacts for all layers"
	@echo "  cleanall      - Clean all build artifacts and data files"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Project structure:"
	@echo "  ethernet/     - Ethernet data link layer implementation"
	@echo "  (Future: network/, transport/, etc.)"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build everything"
	@echo "  make ethernet     # Build Ethernet layer only"
	@echo "  make test         # Run all tests"
	@echo "  make clean        # Clean all build files"
