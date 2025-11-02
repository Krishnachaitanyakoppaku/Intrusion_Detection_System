# Prompt Template for Creating IDS Rules with Gemini

## The Problem
When you ask Gemini to "Detect incoming ICMP ping", it may create invalid rules because it doesn't know the exact syntax required by our Lex/Yacc parser.

## Solution: Use This Exact Prompt

Copy and paste this prompt template to Gemini:

---

**Prompt:**
```
I need you to create an IDS rule using this EXACT syntax format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]"; priority:[number]);

CRITICAL REQUIREMENTS:
1. For ICMP rules: Use "any" for BOTH source and destination ports (even though ICMP doesn't use ports, the parser requires port fields)
2. For TCP/UDP rules: Use actual port numbers or "any"
3. Always end the rule with a semicolon (;)
4. Options must be inside parentheses: (msg:"..."; priority:...)
5. Use "->" for unidirectional direction (not "<>")

Rule request: [YOUR REQUEST HERE]

Provide ONLY the complete rule in the exact format above, nothing else.
```

---

## Example Prompts

### Example 1: ICMP Ping
```
I need you to create an IDS rule using this EXACT syntax format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]"; priority:[number]);

CRITICAL REQUIREMENTS:
1. For ICMP rules: Use "any" for BOTH source and destination ports (even though ICMP doesn't use ports, the parser requires port fields)
2. For TCP/UDP rules: Use actual port numbers or "any"
3. Always end the rule with a semicolon (;)
4. Options must be inside parentheses: (msg:"..."; priority:...)
5. Use "->" for unidirectional direction (not "<>")

Rule request: Detect incoming ICMP ping

Provide ONLY the complete rule in the exact format above, nothing else.
```

**Expected Output:**
```
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3);
```

### Example 2: HTTP Request
```
I need you to create an IDS rule using this EXACT syntax format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]"; priority:[number]);

CRITICAL REQUIREMENTS:
1. For ICMP rules: Use "any" for BOTH source and destination ports (even though ICMP doesn't use ports, the parser requires port fields)
2. For TCP/UDP rules: Use actual port numbers or "any"
3. Always end the rule with a semicolon (;)
4. Options must be inside parentheses: (msg:"..."; priority:...)
5. Use "->" for unidirectional direction (not "<>")

Rule request: Detect incoming HTTP requests on port 80

Provide ONLY the complete rule in the exact format above, nothing else.
```

**Expected Output:**
```
alert tcp any any -> any 80 (msg:"Incoming HTTP Request to Host"; priority:5);
```

### Example 3: SSH Connection
```
I need you to create an IDS rule using this EXACT syntax format:

alert [protocol] [src_ip] [src_port] -> [dst_ip] [dst_port] (msg:"[message]"; priority:[number]);

CRITICAL REQUIREMENTS:
1. For ICMP rules: Use "any" for BOTH source and destination ports (even though ICMP doesn't use ports, the parser requires port fields)
2. For TCP/UDP rules: Use actual port numbers or "any"
3. Always end the rule with a semicolon (;)
4. Options must be inside parentheses: (msg:"..."; priority:...)
5. Use "->" for unidirectional direction (not "<>")

Rule request: Detect incoming SSH connections on port 22

Provide ONLY the complete rule in the exact format above, nothing else.
```

**Expected Output:**
```
alert tcp any any -> any 22 (msg:"Incoming SSH Connection Attempt"; priority:3);
```

## Why Gemini Fails Without This Prompt

Gemini may try to create rules like:
- `alert icmp any -> any (msg:"Ping"; priority:3);` ❌ (missing port fields)
- `alert icmp any 0 -> any 8 (msg:"Ping"; priority:3);` ❌ (using ICMP type/code as ports)
- `alert icmp any any -> any any msg:"Ping" priority:3;` ❌ (missing parentheses)

Our parser grammar requires:
```
action protocol ip_address port direction ip_address port (options);
```

All 7 fields are mandatory, including ports (even for ICMP).

## Quick Reference: Valid Rule Formats

### ICMP Rules
```
alert icmp any any -> any any (msg:"Your Message"; priority:3);
```

### TCP Rules
```
alert tcp any any -> any [port] (msg:"Your Message"; priority:[1-5]);
```

### UDP Rules
```
alert udp any any -> any [port] (msg:"Your Message"; priority:[1-5]);
```

### IP Rules (generic)
```
alert ip any any -> any any (msg:"Your Message"; priority:3);
```

## Testing After Creation

1. Copy the rule Gemini provides
2. Add it to `rules/active.rules`
3. Restart the IDS engine
4. Generate test traffic
5. Check `logs/alerts.log` for alerts

