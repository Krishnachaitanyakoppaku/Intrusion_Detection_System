# Testing Summary - IDS Components

## 🎯 Quick Test (3 Commands)

```bash
# 1. Test components
test_components.bat              # Windows
./test_components.sh             # Linux/WSL

# 2. Capture packets
python scapy_capture.py

# 3. Analyze and generate alerts
make packet_analyzer
./bin/packet_analyzer
```

## 📋 Component Overview

### 1. **Scapy Packet Capture** (`scapy_capture.py`)
   - **Input:** Network interface
   - **Output:** `logs/all_packets.log`
   - **Test:** Run script, generate traffic, check log file

### 2. **Packet Parser** (Compiler Design - Lex/Yacc)
   - **Files:** `src/packet_lexer.l`, `src/packet_parser.y`, `src/packet_parser_helper.c`
   - **Input:** `logs/all_packets.log`
   - **Output:** Parsed packet structures
   - **Test:** Built into packet_analyzer (runs automatically)

### 3. **Rule Matcher** (`src/rule_matcher.c`)
   - **Input:** Parsed packets + Rules from `rules/local.rules`
   - **Output:** `logs/alerts.log`
   - **Test:** Run packet_analyzer, check alerts.log

### 4. **Packet Analyzer** (`src/packet_analyzer.c`)
   - **Purpose:** Main program that ties everything together
   - **Test:** Build and run to process complete workflow

## 🔄 Complete Workflow

```
Network Traffic
      ↓
[Scapy Capture] → logs/all_packets.log
      ↓
[Packet Parser] → Parsed Packets
      ↓
[Rule Matcher] → logs/alerts.log
```

## ✅ Verification Checklist

- [ ] Run `test_components.bat` or `test_components.sh`
- [ ] Verify Scapy installation: `python -c "import scapy"`
- [ ] Test packet capture: `python scapy_capture.py`
- [ ] Check `logs/all_packets.log` has entries
- [ ] Build analyzer: `make packet_analyzer`
- [ ] Run analyzer: `./bin/packet_analyzer`
- [ ] Check `logs/alerts.log` for generated alerts

## 📁 Test Files Created

1. **test_components.sh** / **test_components.bat** - Automated tests
2. **test_workflow.md** - Detailed testing guide
3. **QUICK_TEST.md** - Quick reference
4. **HOW_TO_TEST.txt** - Complete testing instructions

## 🚀 Start Testing Now!

1. Open terminal in project directory
2. Run: `test_components.bat` (Windows) or `./test_components.sh` (Linux)
3. Follow the output instructions

All components are ready - just run the tests! 🎉

