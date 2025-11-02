# Quick Build Guide for Firewall Parser

## The Error You're Seeing

```
Warning: Firewall parser library not found. Build it with: cd firewall && make
```

This means the C library hasn't been built yet. The parser uses Lex/Yacc, which requires compilation.

## Solution

### On Linux/WSL:

```bash
# Method 1: Use build script
cd firewall
bash build_parser.sh

# Method 2: Use Makefile
cd firewall
make

# Method 3: Check if dependencies are installed first
sudo apt-get install flex bison libfl-dev
cd firewall && make
```

### On Windows (without WSL):

You cannot build directly on Windows. Options:

1. **Use WSL** (Windows Subsystem for Linux):
   ```bash
   wsl
   cd /mnt/c/Users/saina/OneDrive/Desktop/CD/Project/Intrusion_Detection_System/firewall
   make
   ```

2. **Use a Linux VM or server**

3. **Skip firewall parsing** - The web server will still work, but firewall event detection won't function

## Verify Build Success

After building, check:

```bash
ls -la build/firewall/libfirewall_parser.so
```

If the file exists, the build was successful!

## Testing

```bash
# Test with sample logs
python firewall/test_parser.py

# Check web interface
# Open: http://localhost:8080
# Look for "Firewall Event Monitor" section
```

## Troubleshooting

**"flex not found"**
```bash
sudo apt-get install flex
```

**"bison not found"**
```bash
sudo apt-get install bison
```

**"libfl-dev not found"**
```bash
sudo apt-get install libfl-dev
```

**Build errors in Makefile**
- Make sure you're in the `firewall/` directory
- Check that `firewall_lexer.l` and `firewall_parser.y` exist
- Try: `make clean && make`


