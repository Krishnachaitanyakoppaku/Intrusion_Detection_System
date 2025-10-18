# IDS DSL Engine

A Domain-Specific Query Language for Intrusion Detection Systems (IDS DSL) built with Lex, Yacc, and libpcap.

## Overview

The IDS DSL Engine is a real-time network intrusion detection system that uses a custom domain-specific language to define security rules. The engine parses these rules using Lex and Yacc, then monitors network traffic using libpcap to detect potential threats and generate alerts.

## Features

- **Custom DSL**: Define security rules using a simple, readable syntax
- **Real-time Monitoring**: Capture and analyze network packets in real-time
- **Flexible Rule Engine**: Support for various protocols (TCP, UDP, ICMP, IP)
- **Content Matching**: Detect specific patterns in packet payloads
- **Alert System**: Generate and log security alerts
- **Configurable**: Customizable network interfaces, timeouts, and logging

## Project Structure

```
ids-dsl-project/
├── bin/                    # Compiled executable
├── build/                  # Object files and build artifacts
├── doc/                    # Documentation
├── include/                # Header files
├── logs/                   # Alert logs
├── rules/                  # DSL rule files
├── src/                    # Source code
├── test_data/              # Test data and samples
└── Makefile               # Build system
```

## Prerequisites

- GCC compiler
- Flex (Lex)
- Bison (Yacc)
- libpcap development libraries
- Root privileges (for packet capture)

### Installation on Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential flex bison libpcap-dev
```

### Installation on CentOS/RHEL:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install flex bison libpcap-devel
```

## Building the Project

1. **Clone or download the project**
2. **Navigate to the project directory**
3. **Build the project**:
   ```bash
   make
   ```

4. **For debug build**:
   ```bash
   make debug
   ```

5. **For release build**:
   ```bash
   make release
   ```

## Usage

### Basic Usage

```bash
# Run with default settings
sudo ./bin/ids_engine

# Specify custom rules file and interface
sudo ./bin/ids_engine -r rules/local.rules -i eth0

# Disable promiscuous mode
sudo ./bin/ids_engine --no-promiscuous

# Custom timeout and log file
sudo ./bin/ids_engine -t 500 -l logs/custom_alerts.log
```

### Command Line Options

- `-r, --rules FILE`: Rules file to load (default: rules/local.rules)
- `-i, --interface IFACE`: Network interface to monitor (default: eth0)
- `-l, --log FILE`: Log file for alerts (default: logs/alerts.log)
- `-p, --no-promiscuous`: Disable promiscuous mode
- `-t, --timeout MS`: Packet capture timeout in milliseconds (default: 1000)
- `-h, --help`: Show help message
- `-v, --version`: Show version information

## DSL Rule Syntax

The IDS DSL uses a simple syntax similar to Snort rules:

```
action protocol source_ip source_port direction dest_ip dest_port (options)
```

### Example Rules

```bash
# SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1"; priority:1)

# Cross-Site Scripting (XSS)
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)

# Port Scan Detection
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)

# ICMP Ping Flood
alert icmp any any -> any any (msg:"ICMP Flood"; priority:4)
```

### Rule Components

- **Action**: `alert`, `log`, `pass`
- **Protocol**: `tcp`, `udp`, `icmp`, `ip`
- **IP Addresses**: Specific IP or `any`
- **Ports**: Specific port number or `any`
- **Direction**: `->` (unidirectional) or `<>` (bidirectional)
- **Options**: `msg`, `content`, `priority`, `sid`, `rev`, `classtype`, `reference`

## Testing

1. **Test the parser**:
   ```bash
   make test
   ```

2. **Test with sample data**:
   ```bash
   # Create test traffic
   ping -c 10 8.8.8.8
   
   # Monitor with IDS
   sudo ./bin/ids_engine -i lo
   ```

## Development

### Adding New Rule Options

1. Add token to `src/lexer.l`
2. Add grammar rule to `src/parser.y`
3. Update AST structures in `include/ast.h`
4. Implement matching logic in `src/engine.c`

### Debugging

Enable debug mode:
```bash
make debug
./bin/ids_engine -r rules/local.rules -i eth0
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with `sudo` for packet capture
2. **Interface Not Found**: Check available interfaces with `ip link show`
3. **No Rules Loaded**: Verify rules file syntax
4. **Build Errors**: Ensure all dependencies are installed

### Debug Information

- Check logs in `logs/alerts.log`
- Use `tcpdump` to verify network traffic
- Enable debug mode for verbose output

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Lex, Yacc, and libpcap
- Inspired by Snort rule syntax
- Designed for educational and research purposes
