# Building the Firewall Parser

The firewall parser uses **Flex** (Lex) and **Bison** (Yacc) for lexical analysis and parsing, following compiler design principles.

## ⚠️ Important: Windows Users

If you're on Windows, you need to build in **WSL** (Windows Subsystem for Linux) or on a Linux machine:

```bash
# In WSL or Linux terminal
cd firewall
make
```

## Dependencies

Install required tools:

```bash
# Ubuntu/Debian
sudo apt-get install flex bison libfl-dev build-essential

# Or on some systems
sudo apt-get install flex bison libfl-dev gcc
```

## Quick Build

**Option 1: Use build script (recommended)**
```bash
cd firewall
bash build_parser.sh
```

**Option 2: Manual build**
```bash
cd firewall
make
```

**Option 3: One-line command**
```bash
cd firewall && make
```

This will:
1. Generate lexer from `firewall_lexer.l` using Flex
2. Generate parser from `firewall_parser.y` using Bison
3. Compile all components
4. Create shared library `build/firewall/libfirewall_parser.so`
5. Create test binary `build/firewall/firewall_parser_test`

## Testing

Test the parser directly:

```bash
# After building
cd build/firewall
./firewall_parser_test "[2025-11-02 15:19:54] server sudo ufw reset"
```

## Integration with Python

The Python wrapper (`firewall_parser_python.py`) uses `ctypes` to call the compiled C library. Update `web_server_complete.py` to use:

```python
from firewall.firewall_parser_python import FirewallEventParser
```

Instead of the old Python-based parser.

## Architecture

```
firewall_lexer.l (Flex)  →  lex.yy.c  →  Token stream
                                              ↓
firewall_parser.y (Bison)  →  parser.tab.c  →  FirewallEvent structure
                                              ↓
firewall_parser_wrapper.c  →  JSON output  →  Python interface
```

## Clean Build

```bash
make clean
make
```

## Installation

Install system-wide:

```bash
sudo make install
```

This installs:
- Library: `/usr/local/lib/libfirewall_parser.so`
- Header: `/usr/local/include/firewall_parser.h`

