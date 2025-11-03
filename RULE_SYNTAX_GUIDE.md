# IDS Rule Syntax Guide

This guide explains the exact syntax required for creating IDS rules that work with our Lex/Yacc parser.

## Basic Rule Format

```
action protocol src_ip src_port -> dst_ip dst_port (options);
```

## Required Components

1. **Action**: `alert`, `log`, or `pass`
2. **Protocol**: `tcp`, `udp`, `icmp`, or `ip`
3. **Source IP**: IP address (e.g., `192.168.1.100`) or `any`
4. **Source Port**: Port number (e.g., `80`) or `any`
5. **Direction**: `->` (unidirectional) or `<>` (bidirectional)
6. **Destination IP**: IP address or `any`
7. **Destination Port**: Port number or `any`
8. **Options**: Rule options in parentheses
9. **Semicolon**: Must end with `;`

## Important Notes

### For ICMP Rules
- **ICMP does NOT use ports**, but the parser grammar requires port fields
- Use `any` for both source and destination ports when writing ICMP rules
- Format: `alert icmp any any -> any any (options);`

### For TCP/UDP Rules
- Use actual port numbers (e.g., `80`, `443`, `22`) or `any`
- Format: `alert tcp any any -> any 80 (options);`

## Options Syntax

Available options:
- `msg:"Your alert message here"`
- `content:"string to match"`
- `priority:1` (1-5, where 1 is highest priority)
- `sid:12345` (rule signature ID)
- `rev:1` (revision number)
- `classtype:"attack-type"`
- `reference:"url"`

Options are separated by semicolons inside parentheses:
```
(msg:"Alert Message"; priority:3)
```

## Examples

### ICMP Ping Detection
```
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3);
```

**Why this works:**
- Uses `any` for ports (ICMP doesn't have ports, but parser requires port fields)
- Uses `->` to specify direction
- Includes required `msg` and `priority` options
- Ends with semicolon

### HTTP Request Detection
```
alert tcp any any -> any 80 (msg:"Incoming HTTP Request to Host"; priority:5);
```

### SSH Connection Detection
```
alert tcp any any -> any 22 (msg:"Incoming SSH Connection Attempt"; priority:3);
```

### DNS Query Detection
```
alert udp any any -> any 53 (msg:"Incoming DNS Query to Host"; priority:5);
```

## Common Mistakes

### ❌ Wrong: Missing semicolon
```
alert icmp any any -> any any (msg:"Ping"; priority:3)
```

### ❌ Wrong: Missing port fields (ICMP still needs "any any")
```
alert icmp any -> any (msg:"Ping"; priority:3);
```

### ❌ Wrong: Missing parentheses
```
alert icmp any any -> any any msg:"Ping"; priority:3;
```

### ❌ Wrong: Using port numbers with ICMP
```
alert icmp any 0 -> any 8 (msg:"Ping"; priority:3);
```

### ✅ Correct
```
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3);
```

## Full Template for AI Assistants (Gemini, ChatGPT, etc.)

When asking an AI to create a rule, provide this template:

```
Create an IDS rule with this format:
alert [protocol] any any -> any [destination_port] (msg:"[message]"; priority:[1-5]);

Where:
- protocol = tcp, udp, icmp, or ip
- destination_port = port number (for tcp/udp) or "any" (for icmp)
- message = your alert description
- priority = 1 (highest) to 5 (lowest)

Example for ICMP ping:
alert icmp any any -> any any (msg:"Incoming ICMP Ping Detected"; priority:3);
```

## Testing Your Rules

After creating a rule, test it by:
1. Adding it to `rules/active.rules`
2. Restarting the IDS engine
3. Generating traffic that should match the rule
4. Checking `logs/alerts.log` for the alert




