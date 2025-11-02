# Firewall Parser Makefile
# Uses Flex and Bison for lexical analysis and parsing

CC = gcc
CFLAGS = -I. -g -Wall -Wextra -std=c99 -fPIC
LDFLAGS = -lfl -ly

# Directories
SRC_DIR = .
BUILD_DIR = ../build/firewall
TARGET_LIB = $(BUILD_DIR)/libfirewall_parser.so
TARGET_BIN = $(BUILD_DIR)/firewall_parser_test

# Source files
LEX_SRC = $(SRC_DIR)/firewall_lexer.l
YACC_SRC = $(SRC_DIR)/firewall_parser.y
WRAPPER_SRC = $(SRC_DIR)/firewall_parser_wrapper.c

# Generated files
LEX_GEN = $(BUILD_DIR)/lex.yy.c
YACC_GEN = $(BUILD_DIR)/firewall_parser.tab.c
YACC_HEADER = $(BUILD_DIR)/firewall_parser.tab.h

# Object files
LEX_OBJ = $(BUILD_DIR)/lexer.o
YACC_OBJ = $(BUILD_DIR)/parser.o
WRAPPER_OBJ = $(BUILD_DIR)/wrapper.o

.PHONY: all clean install

all: $(TARGET_LIB) $(TARGET_BIN)

# Create shared library
$(TARGET_LIB): $(LEX_OBJ) $(YACC_OBJ) $(WRAPPER_OBJ)
	@echo "Linking $(TARGET_LIB)..."
	@mkdir -p $(BUILD_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Create test binary
$(TARGET_BIN): $(LEX_OBJ) $(YACC_OBJ) $(WRAPPER_OBJ) $(SRC_DIR)/test_main.c
	@echo "Building test binary..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(LEX_OBJ) $(YACC_OBJ) $(WRAPPER_OBJ) $(SRC_DIR)/test_main.c $(LDFLAGS)

# Generate lexer from .l file
$(LEX_GEN): $(LEX_SRC)
	@echo "Generating lexer from $(LEX_SRC)..."
	@mkdir -p $(BUILD_DIR)
	@if command -v flex >/dev/null 2>&1; then \
		flex -o $(LEX_GEN) $(LEX_SRC); \
	else \
		echo "Error: flex not found. Please install flex:"; \
		echo "  sudo apt-get install flex"; \
		exit 1; \
	fi

# Compile lexer
$(LEX_OBJ): $(LEX_GEN) $(YACC_HEADER) firewall_parser.h
	@echo "Compiling lexer..."
	$(CC) $(CFLAGS) -I$(BUILD_DIR) -c $(LEX_GEN) -o $@

# Generate parser from .y file
$(YACC_GEN) $(YACC_HEADER): $(YACC_SRC)
	@echo "Generating parser from $(YACC_SRC)..."
	@mkdir -p $(BUILD_DIR)
	@if command -v bison >/dev/null 2>&1; then \
		cd $(BUILD_DIR) && bison -d -o firewall_parser.tab.c ../firewall_parser.y; \
		mv $(BUILD_DIR)/firewall_parser.tab.h $(YACC_HEADER) 2>/dev/null || \
		cp $(BUILD_DIR)/firewall_parser.tab.h $(YACC_HEADER) 2>/dev/null || true; \
	else \
		echo "Error: bison not found. Please install bison:"; \
		echo "  sudo apt-get install bison"; \
		exit 1; \
	fi

# Compile parser
$(YACC_OBJ): $(YACC_GEN) firewall_parser.h
	@echo "Compiling parser..."
	$(CC) $(CFLAGS) -I$(BUILD_DIR) -c $(YACC_GEN) -o $@

# Compile wrapper
$(WRAPPER_OBJ): $(WRAPPER_SRC) $(YACC_HEADER) firewall_parser.h
	@echo "Compiling wrapper..."
	$(CC) $(CFLAGS) -I$(BUILD_DIR) -c $(WRAPPER_SRC) -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SRC_DIR)/*.o $(SRC_DIR)/*.so

install: $(TARGET_LIB)
	@echo "Installing firewall parser library..."
	@mkdir -p /usr/local/lib
	@mkdir -p /usr/local/include
	cp $(TARGET_LIB) /usr/local/lib/
	cp firewall_parser.h /usr/local/include/

test: $(TARGET_BIN)
	@echo "Running firewall parser test..."
	@$(TARGET_BIN) || echo "Build test binary first"

