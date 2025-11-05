# Firewall Parser Makefile
# Uses Flex and Bison for lexical analysis and parsing

CC = gcc
CFLAGS = -I. -g -Wall -Wextra -std=c99 -fPIC
LDFLAGS = -lfl

# Directories
SRC_DIR = .
BUILD_DIR = ../build/firewall
BIN_DIR = ../bin
TARGET_LIB = $(BUILD_DIR)/libfirewall_parser.so
TARGET_BIN = $(BUILD_DIR)/firewall_parser_test
FIREWALL_ANALYZER = $(BIN_DIR)/firewall_analyzer

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

.PHONY: all clean install firewall_analyzer

all: $(TARGET_LIB) $(TARGET_BIN) $(FIREWALL_ANALYZER)

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

# Create firewall analyzer binary (similar to bin/packet_analyzer)
FIREWALL_ANALYZER_OBJ = $(BUILD_DIR)/firewall_analyzer.o

$(FIREWALL_ANALYZER_OBJ): $(SRC_DIR)/firewall_analyzer.c firewall_parser.h
	@echo "Compiling firewall analyzer..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(BUILD_DIR) -c $(SRC_DIR)/firewall_analyzer.c -o $@

$(FIREWALL_ANALYZER): $(LEX_OBJ) $(YACC_OBJ) $(FIREWALL_ANALYZER_OBJ)
	@echo "Linking firewall analyzer..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(LEX_OBJ) $(YACC_OBJ) $(FIREWALL_ANALYZER_OBJ) $(LDFLAGS)

# Generate parser from .y file (must be first)
$(YACC_GEN) $(YACC_HEADER): $(YACC_SRC)
	@echo "Generating parser from $(YACC_SRC)..."
	@mkdir -p $(BUILD_DIR)
	@if command -v bison >/dev/null 2>&1; then \
		bison -d -o $(YACC_GEN) $(YACC_SRC); \
		mv $(BUILD_DIR)/firewall_parser.tab.h $(YACC_HEADER) 2>/dev/null || true; \
	else \
		echo "Error: bison not found. Please install bison:"; \
		echo "  sudo apt-get install bison"; \
		exit 1; \
	fi

# Generate lexer from .l file (after parser header is generated)
$(LEX_GEN): $(LEX_SRC) $(YACC_HEADER)
	@echo "Generating lexer from $(LEX_SRC)..."
	@mkdir -p $(BUILD_DIR)
	@if command -v flex >/dev/null 2>&1; then \
		flex -o $(LEX_GEN) $(LEX_SRC); \
	else \
		echo "Error: flex not found. Please install flex:"; \
		echo "  sudo apt-get install flex"; \
		exit 1; \
	fi

# Compile lexer (need parser header first)
$(LEX_OBJ): $(LEX_GEN) $(YACC_HEADER) firewall_parser.h
	@echo "Compiling lexer..."
	@test -f $(YACC_HEADER) || (echo "Error: $(YACC_HEADER) not found"; exit 1)
	$(CC) $(CFLAGS) -I$(BUILD_DIR) -I. -include $(YACC_HEADER) -c $(LEX_GEN) -o $@

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

