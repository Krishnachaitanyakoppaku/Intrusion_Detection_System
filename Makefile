# IDS DSL Engine Makefile
# Compiler and flags
CC = gcc
CFLAGS = -I./include -g -Wall -Wextra -std=c99
LDFLAGS = -lfl -lpcap -lcurl -ljson-c -lm

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
TARGET = $(BIN_DIR)/ids_engine

# Automatically find all C, Yacc, and Lex source files
C_SRCS = $(wildcard $(SRC_DIR)/*.c)
Y_SRCS = $(wildcard $(SRC_DIR)/*.y)
L_SRCS = $(wildcard $(SRC_DIR)/*.l)

# Generate object file names - exclude generated files
C_OBJS = $(filter-out $(SRC_DIR)/lex.yy.c $(SRC_DIR)/parser.tab.c, $(C_SRCS))
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(filter %.c, $(C_OBJS))) \
       $(patsubst $(SRC_DIR)/%.y, $(BUILD_DIR)/parser.o, $(filter %.y, $(Y_SRCS))) \
       $(patsubst $(SRC_DIR)/%.l, $(BUILD_DIR)/lexer.o, $(filter %.l, $(L_SRCS)))

# Generated files
GENERATED_FILES = $(SRC_DIR)/lex.yy.c $(SRC_DIR)/parser.tab.c include/parser.h

.PHONY: all clean install uninstall test

# Default target
all: $(TARGET)

# Main target
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete! Executable is at $(TARGET)"

# Rule for compiling .c files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling .y file with Bison
$(BUILD_DIR)/parser.o: $(SRC_DIR)/parser.y
	@echo "Generating parser from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v bison >/dev/null 2>&1; then \
		bison -d -o $(SRC_DIR)/parser.tab.c $(SRC_DIR)/parser.y; \
		cp $(SRC_DIR)/parser.tab.h include/parser.h; \
		$(CC) $(CFLAGS) -c $(SRC_DIR)/parser.tab.c -o $@; \
	else \
		echo "Error: bison not found. Please install bison and flex:"; \
		echo "  sudo apt-get install bison flex libpcap-dev"; \
		exit 1; \
	fi

# Special rule for ast.c (depends on parser.h)
$(BUILD_DIR)/ast.o: $(SRC_DIR)/ast.c $(BUILD_DIR)/parser.o
	@echo "Compiling $<..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling .l file with Flex
$(BUILD_DIR)/lexer.o: $(SRC_DIR)/lexer.l
	@echo "Generating lexer from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v flex >/dev/null 2>&1; then \
		flex -o $(SRC_DIR)/lex.yy.c $(SRC_DIR)/lexer.l; \
		$(CC) $(CFLAGS) -c $(SRC_DIR)/lex.yy.c -o $@; \
	else \
		echo "Error: flex not found. Please install bison and flex:"; \
		echo "  sudo apt-get install bison flex libpcap-dev"; \
		exit 1; \
	fi

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f $(GENERATED_FILES)
	@echo "Cleanup complete."

# Install the binary (requires root)
install: $(TARGET)
	@echo "Installing IDS Engine..."
	@mkdir -p /usr/local/bin
	cp $(TARGET) /usr/local/bin/
	@echo "Installation complete."

# Uninstall the binary
uninstall:
	@echo "Uninstalling IDS Engine..."
	rm -f /usr/local/bin/ids_engine
	@echo "Uninstallation complete."

# Test the parser with sample rules
test: $(TARGET)
	@echo "Testing parser with sample rules..."
	@if [ -f rules/local.rules ]; then \
		echo "Rules file found, testing parser..."; \
		./$(TARGET) --help; \
	else \
		echo "No rules file found. Please create rules/local.rules first."; \
	fi

# Show help
help:
	@echo "IDS DSL Engine Makefile"
	@echo "======================"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build the IDS engine (default)"
	@echo "  clean     - Remove all build artifacts"
	@echo "  install   - Install the binary to /usr/local/bin"
	@echo "  uninstall - Remove the binary from /usr/local/bin"
	@echo "  test      - Test the parser with sample rules"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build the project"
	@echo "  make clean        # Clean build artifacts"
	@echo "  make install      # Install (requires root)"
	@echo "  make test         # Test the parser"

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

# Release build
release: CFLAGS += -O2 -DNDEBUG
release: clean $(TARGET)
