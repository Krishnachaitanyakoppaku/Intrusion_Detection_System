# IDS DSL Engine - Installation Guide

## Prerequisites

The IDS DSL Engine requires the following tools and libraries:

### Required Tools
- **GCC Compiler**: For compiling C code
- **Bison**: For parsing Yacc grammar files
- **Flex**: For lexical analysis
- **libpcap**: For network packet capture

### Installation Commands

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential bison flex libpcap-dev
```

#### CentOS/RHEL/Fedora:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install bison flex libpcap-devel
```

#### macOS (with Homebrew):
```bash
brew install bison flex libpcap
```

#### Arch Linux:
```bash
sudo pacman -S base-devel bison flex libpcap
```

## Building the Project

1. **Navigate to the project directory**:
   ```bash
   cd /path/to/ids-dsl-project
   ```

2. **Build the project**:
   ```bash
   make
   ```

3. **For debug build**:
   ```bash
   make debug
   ```

4. **For release build**:
   ```bash
   make release
   ```

## Installation

After building, you can install the binary system-wide:

```bash
sudo make install
```

This will install the `ids_engine` binary to `/usr/local/bin/`.

## Verification

To verify the installation:

1. **Check if the binary was built**:
   ```bash
   ls -la bin/ids_engine
   ```

2. **Test the help message**:
   ```bash
   ./bin/ids_engine --help
   ```

3. **Test with sample rules**:
   ```bash
   make test
   ```

## Troubleshooting

### Common Issues

1. **"bison not found"**:
   - Install bison: `sudo apt-get install bison`

2. **"flex not found"**:
   - Install flex: `sudo apt-get install flex`

3. **"libpcap not found"**:
   - Install libpcap: `sudo apt-get install libpcap-dev`

4. **Permission denied**:
   - The IDS engine requires root privileges for packet capture
   - Run with `sudo ./bin/ids_engine`

5. **Interface not found**:
   - Check available interfaces: `ip link show`
   - Use a valid interface name: `sudo ./bin/ids_engine -i eth0`

### Build Issues

If you encounter build errors:

1. **Clean and rebuild**:
   ```bash
   make clean
   make
   ```

2. **Check dependencies**:
   ```bash
   which gcc bison flex
   ```

3. **Verify libpcap**:
   ```bash
   pkg-config --cflags --libs libpcap
   ```

## Next Steps

After successful installation:

1. **Create custom rules** in `rules/local.rules`
2. **Test with sample traffic**:
   ```bash
   sudo ./bin/ids_engine -i lo
   ```
3. **Monitor alerts** in `logs/alerts.log`

## Uninstallation

To remove the installed binary:

```bash
sudo make uninstall
```

This will remove the `ids_engine` binary from `/usr/local/bin/`.
