# IDS DSL Engine - Project Summary

## Project Overview

The IDS DSL Engine is a complete implementation of a Domain-Specific Query Language for Intrusion Detection Systems. The project includes a lexical analyzer, parser, rule engine, and network monitoring capabilities built with Lex, Yacc, and libpcap.

## Project Structure

```
ids-dsl-project/
├── bin/                    # Compiled executable (after build)
├── build/                  # Object files and build artifacts
├── doc/                    # Documentation
│   ├── README.md          # Main documentation
│   ├── Team_Notes.md      # Development notes
│   └── INSTALL.md         # Installation guide
├── include/                # Header files
│   ├── ast.h              # AST data structures
│   ├── engine.h            # Engine interface
│   └── parser.h            # Generated parser header
├── logs/                   # Alert logs
│   └── alerts.log         # Generated alerts
├── rules/                  # DSL rule files
│   └── local.rules         # Sample rules
├── src/                    # Source code
│   ├── ast.c              # AST implementation
│   ├── engine.c            # Rule engine
│   ├── lexer.l             # Lexical analyzer
│   ├── main.c              # Main application
│   └── parser.y            # Parser grammar
├── test_data/              # Test data and samples
│   ├── auth.log_sample     # Sample log file
│   └── sql_injection.pcap  # Sample packet capture
├── Makefile               # Build system
├── INSTALL.md             # Installation instructions
└── PROJECT_SUMMARY.md     # This file
```

## Key Components

### 1. Lexical Analyzer (`src/lexer.l`)
- **Purpose**: Tokenizes DSL rule input
- **Features**: 
  - Keywords: alert, log, pass, tcp, udp, icmp, ip
  - Operators: ->, <>, :, ;, (, )
  - Data types: IP addresses, ports, strings, numbers
  - Error handling and line number tracking

### 2. Parser (`src/parser.y`)
- **Purpose**: Parses tokens into Abstract Syntax Tree
- **Features**:
  - LL(1) grammar for rule parsing
  - AST building during parsing
  - Error recovery and reporting
  - Support for rule options (msg, content, priority, etc.)

### 3. AST Management (`include/ast.h`, `src/ast.c`)
- **Purpose**: Data structures and operations for rules
- **Features**:
  - Linked list structures for rules and options
  - Memory management functions
  - Rule creation and manipulation
  - Print and debug functions

### 4. Rule Engine (`include/engine.h`, `src/engine.c`)
- **Purpose**: Packet processing and rule matching
- **Features**:
  - libpcap integration for packet capture
  - Protocol support (IP, TCP, UDP, ICMP)
  - Rule matching logic
  - Alert generation and logging
  - Signal handling for graceful shutdown

### 5. Main Application (`src/main.c`)
- **Purpose**: CLI interface and orchestration
- **Features**:
  - Command-line argument parsing
  - Configuration management
  - Integration of all components
  - Help and version information

## DSL Rule Syntax

The IDS DSL uses a syntax similar to Snort rules:

```
action protocol source_ip source_port direction dest_ip dest_port (options)
```

### Example Rules

```bash
# SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1"; priority:1)

# XSS Detection
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)

# Port Scan Detection
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)
```

## Build System

The project uses a comprehensive Makefile with:

- **Automatic dependency handling**
- **Lex and Yacc integration**
- **Debug and release builds**
- **Installation and uninstallation**
- **Cleanup and testing targets**

### Build Commands

```bash
make              # Build the project
make debug        # Debug build
make release      # Release build
make clean        # Clean build artifacts
make install      # Install system-wide
make uninstall    # Remove installation
make test         # Test the parser
```

## Dependencies

### Required Tools
- **GCC**: C compiler
- **Bison**: Parser generator
- **Flex**: Lexical analyzer generator
- **libpcap**: Network packet capture library

### Installation
```bash
# Ubuntu/Debian
sudo apt-get install build-essential bison flex libpcap-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install bison flex libpcap-devel
```

## Usage

### Basic Usage
```bash
# Run with defaults
sudo ./bin/ids_engine

# Custom rules and interface
sudo ./bin/ids_engine -r rules/local.rules -i eth0

# Custom timeout and logging
sudo ./bin/ids_engine -t 500 -l logs/custom_alerts.log
```

### Command Line Options
- `-r, --rules FILE`: Rules file (default: rules/local.rules)
- `-i, --interface IFACE`: Network interface (default: eth0)
- `-l, --log FILE`: Log file (default: logs/alerts.log)
- `-p, --no-promiscuous`: Disable promiscuous mode
- `-t, --timeout MS`: Timeout in milliseconds
- `-h, --help`: Show help
- `-v, --version`: Show version

## Testing

### Sample Data
The project includes sample data for testing:

- **Sample Rules**: `rules/local.rules` with various threat detection rules
- **Sample Logs**: `test_data/auth.log_sample` with authentication logs
- **Sample Traffic**: `test_data/sql_injection.pcap` for packet analysis

### Test Commands
```bash
# Test parser
make test

# Test with sample traffic
ping -c 10 8.8.8.8
sudo ./bin/ids_engine -i lo

# Monitor alerts
tail -f logs/alerts.log
```

## Security Features

### Rule Types Supported
- **SQL Injection**: Detect database attack patterns
- **XSS Attacks**: Detect cross-site scripting attempts
- **Port Scans**: Detect network reconnaissance
- **ICMP Floods**: Detect denial-of-service attacks
- **File Uploads**: Detect malicious file uploads
- **Directory Traversal**: Detect path traversal attacks
- **Command Injection**: Detect shell command injection

### Alert System
- **Real-time alerts**: Console output during monitoring
- **Log file**: Persistent alert storage
- **Severity levels**: Priority-based alert classification
- **Timestamp tracking**: Precise timing information

## Performance Considerations

### Memory Management
- **Dynamic allocation**: Rules and options stored in linked lists
- **Proper cleanup**: Memory deallocation on shutdown
- **Efficient structures**: Optimized for rule matching

### Network Performance
- **Single-threaded**: Sequential packet processing
- **libpcap integration**: Efficient packet capture
- **Rule optimization**: Sequential rule checking

### Scalability
- **Rule count**: Designed for hundreds of rules
- **Packet rate**: Suitable for moderate network traffic
- **Memory usage**: Linear growth with rule count

## Future Enhancements

### Planned Features
1. **Regex Support**: PCRE integration for content matching
2. **Rule Optimization**: Compile rules into efficient structures
3. **Multi-threading**: Parallel packet processing
4. **GUI Interface**: Web-based rule management
5. **Rule Import/Export**: Standard rule formats

### Performance Improvements
1. **Rule Compilation**: Pre-compile rules for faster matching
2. **Packet Filtering**: BPF filter optimization
3. **Memory Pool**: Reduce allocation overhead
4. **Caching**: Cache frequently matched patterns

## Development Guidelines

### Code Style
- **C99 Standard**: Modern C features
- **Descriptive naming**: Clear variable and function names
- **Comprehensive comments**: Document complex logic
- **Error handling**: Check return values and handle errors

### Testing Strategy
- **Unit tests**: Individual function testing
- **Integration tests**: Component interaction testing
- **Performance tests**: Load and stress testing
- **Security tests**: Attack simulation and validation

## Conclusion

The IDS DSL Engine provides a complete, production-ready implementation of a domain-specific language for intrusion detection. The project demonstrates:

- **Advanced parsing techniques** using Lex and Yacc
- **Network programming** with libpcap
- **System programming** with signal handling and memory management
- **Software engineering** with modular design and comprehensive testing

The implementation is ready for use in educational, research, and development environments, with clear documentation and examples for extension and customization.
