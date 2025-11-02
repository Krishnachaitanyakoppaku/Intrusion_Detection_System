# How to Run host_setup_auto.sh

## Issue: "command not found"

If you get `command not found` when running `sudo host_setup_auto.sh`, use one of these methods:

## Method 1: Run with bash (Recommended)

```bash
cd firewall
sudo bash host_setup_auto.sh
```

## Method 2: Make executable and run directly

```bash
cd firewall
chmod +x host_setup_auto.sh
sudo ./host_setup_auto.sh
```

## Method 3: Use full path

```bash
sudo bash /mnt/c/Users/saina/OneDrive/Desktop/CD/Project/Intrusion_Detection_System/firewall/host_setup_auto.sh
```

## Why it happens

The error `command not found` occurs because:
- The script is not in your system PATH
- The script needs to be executed by bash explicitly
- The script may not have execute permissions

## Quick Fix for WSL/Linux

```bash
# Navigate to firewall directory
cd firewall

# Run with bash (no execute permission needed)
sudo bash host_setup_auto.sh
```

## Verify it works

Before running, verify you're in the right directory:

```bash
pwd
# Should show: .../Intrusion_Detection_System/firewall

ls -la host_setup_auto.sh
# Should show the file exists
```

## Common Mistakes

❌ **Wrong:** `sudo host_setup_auto.sh` (script not in PATH)  
✅ **Correct:** `sudo bash host_setup_auto.sh`

❌ **Wrong:** `sudo ./host_setup_auto.sh` (without execute permission)  
✅ **Correct:** `chmod +x host_setup_auto.sh` then `sudo ./host_setup_auto.sh`  
✅ **Or:** `sudo bash host_setup_auto.sh` (no chmod needed)


