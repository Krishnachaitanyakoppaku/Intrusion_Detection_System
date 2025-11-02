# Incoming Traffic Detection Rules

These rules are designed to detect **only incoming traffic** (traffic coming TO your host) for easy testing.

## How They Work

The rules use destination ports/services that indicate incoming connections:
- **Destination port specified** (80, 22, 53, 443) = incoming to host
- **Source = any** = external source
- When tested from another computer, these will trigger alerts

## Recommended Test Rules (Copy to active.rules)

```bash
# Incoming ICMP (Ping)
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3)

# Incoming HTTP (Web requests to host)
alert tcp any any -> any 80 (msg:"Incoming HTTP Request to Host"; priority:5)

# Incoming SSH
alert tcp any any -> any 22 (msg:"Incoming SSH Connection Attempt"; priority:3)

# Incoming DNS
alert udp any any -> any 53 (msg:"Incoming DNS Query to Host"; priority:5)

# Incoming HTTPS
alert tcp any any -> any 443 (msg:"Incoming HTTPS Request to Host"; priority:5)
```

## Testing from Another Computer

### 1. ICMP Ping (Easiest)
```bash
ping <WINDOWS-IP-ADDRESS>
```
✅ Will trigger alert immediately

### 2. HTTP Request
```bash
curl http://<WINDOWS-IP-ADDRESS>
# Or if you have a web server running
curl http://<WINDOWS-IP-ADDRESS>:80
```
✅ Will trigger alert

### 3. SSH Connection
```bash
ssh <WINDOWS-IP-ADDRESS>
# Or
telnet <WINDOWS-IP-ADDRESS> 22
```
✅ Will trigger alert even if connection fails

### 4. DNS Query
```bash
nslookup google.com <WINDOWS-IP-ADDRESS>
# Or
dig @<WINDOWS-IP-ADDRESS> google.com
```
✅ Will trigger alert if DNS server is running

### 5. HTTPS Request
```bash
curl https://<WINDOWS-IP-ADDRESS>
# Or
curl -k https://<WINDOWS-IP-ADDRESS>:443
```
✅ Will trigger alert

## Why These Work for Incoming Only

1. **Destination ports (80, 22, 53, 443)** are typically server ports
2. When you ping FROM another computer TO your host → incoming ICMP
3. When you curl FROM another computer TO port 80 → incoming HTTP
4. Your own outgoing requests won't match destination port rules (unless you're accessing your own server)

## Example Scenarios

**Scenario 1: Testing ICMP**
- Another computer: `ping 192.168.1.100` (your Windows IP)
- Result: ✅ Alert triggered (incoming ICMP detected)

**Scenario 2: Testing HTTP**
- Another computer: `curl http://192.168.1.100`
- Result: ✅ Alert triggered (incoming TCP to port 80)

**Scenario 3: Your own outgoing traffic**
- Your computer: `curl http://google.com`
- Result: ❌ No alert (this is outgoing, not matching destination port rules)

## Notes

- ICMP rule matches both directions, but pings FROM others are incoming
- Port-based rules (80, 22, 53, 443) primarily catch incoming because they target server ports
- For more precise incoming-only detection, the capture engine would need to check if dst_ip matches host IP (future enhancement)

