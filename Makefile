# IDS DSL Engine Makefile
# Compiler and flags
CC = gcc
CFLAGS = -I./include -g -Wall -Wextra -std=c99
LDFLAGS = -lfl -lpcap -lm

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin
TARGET = $(BIN_DIR)/ids_engine

# Automatically find all C, Yacc, and Lex source files
C_SRCS = $(wildcard $(SRC_DIR)/*.c)
# Separate parsers: rules parser (parser.y/lexer.l) and packet parser (packet_parser.y/packet_lexer.l)
RULES_Y = $(SRC_DIR)/parser.y
RULES_L = $(SRC_DIR)/lexer.l
PACKET_Y = $(SRC_DIR)/packet_parser.y
PACKET_L = $(SRC_DIR)/packet_lexer.l

# Generate object file names - exclude generated files
C_OBJS = $(filter-out $(SRC_DIR)/lex.yy.c $(SRC_DIR)/parser.tab.c $(SRC_DIR)/packet_lex.yy.c $(SRC_DIR)/packet_parser.tab.c, $(C_SRCS))
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(filter %.c, $(C_OBJS))) \
       $(BUILD_DIR)/parser.o $(BUILD_DIR)/lexer.o

# Generated files
GENERATED_FILES = $(SRC_DIR)/lex.yy.c $(SRC_DIR)/parser.tab.c include/parser.h \
                  $(SRC_DIR)/packet_lex.yy.c $(SRC_DIR)/packet_parser.tab.c

# Packet analyzer target
PACKET_ANALYZER_TARGET = $(BIN_DIR)/packet_analyzer

.PHONY: all clean install uninstall packet_analyzer

# Default target
all: $(TARGET)

# Main target
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete! Executable is at $(TARGET)"

# Packet analyzer objects (compiler-design pipeline for logs → alerts)
PACKET_ANALYZER_OBJS = \
	$(BUILD_DIR)/packet_analyzer.o \
	$(BUILD_DIR)/packet_parser_helper.o \
	$(BUILD_DIR)/rule_matcher.o \
	$(BUILD_DIR)/ast.o \
	$(BUILD_DIR)/packet_parser.o \
	$(BUILD_DIR)/packet_lexer.o \
	$(BUILD_DIR)/parser.o \
	$(BUILD_DIR)/lexer.o

# Packet analyzer target
packet_analyzer: $(PACKET_ANALYZER_TARGET)

$(PACKET_ANALYZER_TARGET): $(PACKET_ANALYZER_OBJS)
	@echo "Linking $(PACKET_ANALYZER_TARGET)..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete! Executable is at $(PACKET_ANALYZER_TARGET)"

# Rule for compiling .c files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule for compiling rules .y file with Bison
$(BUILD_DIR)/parser.o: $(RULES_Y)
	@echo "Generating parser from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v bison >/dev/null 2>&1; then \
		bison -d -o $(SRC_DIR)/parser.tab.c $(RULES_Y); \
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

# Rule for compiling rules .l file with Flex
$(BUILD_DIR)/lexer.o: $(RULES_L)
	@echo "Generating lexer from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v flex >/dev/null 2>&1; then \
		flex -o $(SRC_DIR)/lex.yy.c $(RULES_L); \
		$(CC) $(CFLAGS) -c $(SRC_DIR)/lex.yy.c -o $@; \
	else \
		echo "Error: flex not found. Please install bison and flex:"; \
		echo "  sudo apt-get install bison flex libpcap-dev"; \
		exit 1; \
	fi

# Rule for compiling packet .y file with Bison
$(BUILD_DIR)/packet_parser.o: $(PACKET_Y)
	@echo "Generating packet parser from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v bison >/dev/null 2>&1; then \
		bison -d -o $(SRC_DIR)/packet_parser.tab.c $(PACKET_Y); \
		$(CC) $(CFLAGS) -c $(SRC_DIR)/packet_parser.tab.c -o $@; \
	else \
		echo "Error: bison not found. Please install bison and flex:"; \
		echo "  sudo apt-get install bison flex libpcap-dev"; \
		exit 1; \
	fi

# Rule for compiling packet .l file with Flex
$(BUILD_DIR)/packet_lexer.o: $(PACKET_L)
	@echo "Generating packet lexer from $<..."
	@mkdir -p $(BUILD_DIR)
	@if command -v flex >/dev/null 2>&1; then \
		flex -o $(SRC_DIR)/packet_lex.yy.c $(PACKET_L); \
		$(CC) $(CFLAGS) -c $(SRC_DIR)/packet_lex.yy.c -o $@; \
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
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build the project"
	@echo "  make clean        # Clean build artifacts"
	@echo "  make install      # Install (requires root)"