# Firewall Setup Directory

This directory contains all firewall-related configuration files and scripts for the Intrusion Detection System.

## Files

- `host_setup_auto.sh` - Automated firewall host setup script
- `client_setup_auto.sh` - Client setup script to forward syslog to host
- `firewall_lexer.l` - **Lex/Flex lexical analyzer** for tokenizing firewall logs
- `firewall_parser.y` - **Bison/Yacc parser** for parsing firewall commands
- `firewall_parser.h` - C header file with data structures
- `firewall_parser_wrapper.c` - C wrapper for Python integration
- `firewall_parser_python.py` - Python wrapper using ctypes
- `Makefile` - Build system for compiling Lex/Yacc parser
- `firewall_config.txt` - Generated configuration file with network settings
- `logs/` - Directory containing firewall logs
- `test_parser.py` - Script to generate sample log entries for testing
- `test_main.c` - C test program for the parser
- `BUILD.md` - Build instructions for Lex/Yacc parser
- `DEPENDENCIES.md` - Dependency documentation
- `USAGE.md` - Usage instructions

## Compiler Design Implementation

This firewall parser uses **complete compiler design techniques**:

1. **Lexical Analysis (Lex/Flex)**: `firewall_lexer.l`
   - Tokenizes firewall log entries
   - Recognizes commands, IPs, timestamps, hostnames
   - Case-insensitive pattern matching

2. **Syntax Analysis (Yacc/Bison)**: `firewall_parser.y`
   - Parses token stream into abstract syntax
   - Builds FirewallEvent structures
   - Grammar rules for firewall commands

3. **Build System**: Makefile
   - Compiles Lex → C code
   - Compiles Yacc → C code
   - Links into shared library

See [BUILD.md](BUILD.md) for compilation instructions.
See [QUICK_BUILD.md](QUICK_BUILD.md) if you're seeing build errors.

## Dependencies

See [DEPENDENCIES.md](DEPENDENCIES.md) for complete dependency list.

**Quick Summary:**
- Linux (Debian/Ubuntu)
- Root/Sudo access
- Two network interfaces (internet + client network)
- Packages: `ufw`, `rsyslog`, `iptables-persistent`, `net-tools` (auto-installed)

## Usage

### Host Setup

**Important:** Always run the script with `bash` explicitly.

```bash
cd firewall
sudo bash host_setup_auto.sh
```

**Troubleshooting:** If you get "command not found", see [USAGE.md](USAGE.md) for detailed instructions.

This script will:
- Auto-detect internet and client interfaces
- Configure rsyslog to receive remote logs on TCP/UDP port 514
- Set up NAT/MASQUERADE for internet sharing
- Configure UFW firewall rules
- Assign 192.168.50.1/24 to the client interface
- Store all logs in `firewall/logs/firewall.log`

### Log Files

All firewall and network logs are stored in `firewall/logs/firewall.log`.

The log file contains:
- Remote syslog messages from connected clients
- Network traffic logs
- Firewall events

### Configuration

After running the setup script, network configuration details are saved to `firewall_config.txt`:
- Internet interface name
- Client interface name
- Client network subnet
- Log file location

## Network Architecture

```
Internet (via $INET_IF)
    |
    | [NAT/MASQUERADE]
    |
Host (192.168.50.1/24 via $CLIENT_IF)
    |
    |
Clients (192.168.50.x/24)
```

## Client Configuration

After host setup, configure clients to forward syslog:

1. **Connect clients to the host network** (WiFi hotspot or ethernet)

2. **Run client setup script on each client:**
   ```bash
   # Copy client_setup_auto.sh to client machine, then:
   sudo bash firewall/client_setup_auto.sh
   ```
   
   The script will prompt for the firewall host IP address.

3. **The script will:**
   - Install rsyslog if needed
   - Configure forwarding to host IP:514
   - Test connectivity
   - Send a test log message

**Alternative manual setup:**
```bash
# On client, edit /etc/rsyslog.d/10-forward.conf
echo "*.* @@HOST_IP:514" | sudo tee /etc/rsyslog.d/10-forward.conf
sudo systemctl restart rsyslog
```

## Firewall Event Monitoring

The firewall parser automatically detects critical security events in logs, including:

### Detected Events

**Critical Severity:**
- `ufw reset` - Firewall rules reset
- `ufw disable` - Firewall disabled
- `iptables -F` / `iptables --flush` - All iptables rules deleted
- `iptables -X` - iptables chains deleted
- `systemctl stop firewalld` - Firewall service stopped

**High Severity:**
- `chmod 777/666/000` on system files
- Privilege escalation attempts (`su -`, `sudo su`)

**Medium Severity:**
- iptables rule modifications (`iptables -A`, `iptables -D`)
- Firewall configuration reloads
- Root/sudo firewall commands

**Low Severity:**
- `ufw allow/deny/reject` - Rule additions
- `ufw enable` - Firewall enabled

### Web Interface

The firewall events are automatically displayed in the web interface at:
- **URL:** `http://localhost:8080`
- **Section:** "🔥 Firewall Event Monitor"

Features:
- Real-time event streaming via Server-Sent Events (SSE)
- Interactive event cards with severity indicators
- Statistics dashboard showing event counts by severity
- Filter by severity (Critical, High, Medium, Low)
- Expandable raw log view for each event
- Automatic detection of commands, source IPs, and timestamps

### Testing the Parser

Generate sample log entries:
```bash
python firewall/test_parser.py
```

Test C parser (after building):
```bash
cd firewall && make
cd build/firewall
./firewall_parser_test "[2025-11-02 15:19:54] server sudo ufw reset"
```

## Troubleshooting

- Check `firewall/logs/firewall.log` for incoming logs
- Verify interfaces: `ip addr show`
- Check UFW status: `sudo ufw status verbose`
- View iptables rules: `sudo iptables -t nat -L -v`
- Build parser: `cd firewall && make`
- Test parser: `python firewall/test_parser.py` (generates test logs)

