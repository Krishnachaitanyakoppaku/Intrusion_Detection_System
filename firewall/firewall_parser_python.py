#!/usr/bin/env python3
"""
Python wrapper for C-based firewall parser (Lex/Yacc)
Uses ctypes to interface with compiled C library
"""

import os
import sys
import ctypes
import json
from typing import List, Dict, Optional

class FirewallEventParser:
    """Parser for firewall logs using Lex/Yacc-based C parser"""
    
    def __init__(self, log_file_path: str = None):
        """Initialize parser with log file path"""
        if log_file_path is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.log_file = os.path.join(script_dir, 'logs', 'firewall.log')
        else:
            self.log_file = log_file_path
        
        # Load the C library
        self.lib = self._load_library()
        if not self.lib:
            # Graceful fallback - allow initialization but parsing will fail gracefully
            # Don't print warning here - will be shown when actual parsing is attempted
            self.lib = None
    
    def _load_library(self):
        """Load the compiled C library"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        build_dir = os.path.join(os.path.dirname(script_dir), 'build', 'firewall')
        lib_path = os.path.join(build_dir, 'libfirewall_parser.so')
        
        # Try multiple possible locations
        paths = [
            lib_path,
            os.path.join(script_dir, 'libfirewall_parser.so'),
            '/usr/local/lib/libfirewall_parser.so',
        ]
        
        for path in paths:
            if os.path.exists(path):
                try:
                    lib = ctypes.CDLL(path)
                    # Set up function signatures
                    lib.parse_log_line_to_json.argtypes = [ctypes.c_char_p]
                    lib.parse_log_line_to_json.restype = ctypes.c_char_p
                    lib.parse_log_buffer_to_json.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
                    lib.parse_log_buffer_to_json.restype = ctypes.c_char_p
                    return lib
                except OSError as e:
                    # Only print detailed error in debug mode
                    if os.environ.get('DEBUG', ''):
                        print(f"Debug: Could not load {path}: {e}")
                    continue
        
        return None
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line using C parser"""
        if not line or not line.strip():
            return None
        
        if not self.lib:
            # Try to reload library (maybe it was built after initialization)
            self.lib = self._load_library()
            if not self.lib:
                return None
        
        try:
            # Call C function
            result = self.lib.parse_log_line_to_json(line.encode('utf-8'))
            if not result:
                return None
            
            # Parse JSON result
            json_str = result.decode('utf-8')
            events = json.loads(json_str)
            
            if events and len(events) > 0:
                event = events[0]  # Take first event
                event['raw_line'] = line.strip()
                return event
            
        except Exception as e:
            print(f"Error parsing log line with C parser: {e}")
            return None
        
        return None
    
    def parse_log_file(self, max_lines: int = 1000) -> List[Dict]:
        """Parse firewall log file and return detected events"""
        events = []
        
        if not os.path.exists(self.log_file):
            return events
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Process from most recent
                for line in reversed(lines[-max_lines:]):
                    event = self.parse_log_line(line)
                    if event:
                        events.append(event)
        except Exception as e:
            print(f"Error parsing log file: {e}")
        
        # Return in chronological order (oldest first)
        return list(reversed(events))
    
    def get_recent_events(self, count: int = 50) -> List[Dict]:
        """Get most recent firewall events"""
        all_events = self.parse_log_file(max_lines=1000)
        return all_events[-count:] if len(all_events) > count else all_events
    
    def get_critical_events(self) -> List[Dict]:
        """Get only critical severity events"""
        all_events = self.parse_log_file()
        return [e for e in all_events if e.get('severity') == 'critical']
    
    def get_stats(self) -> Dict:
        """Get statistics about firewall events"""
        events = self.parse_log_file()
        
        stats = {
            'total_events': len(events),
            'critical': len([e for e in events if e.get('severity') == 'critical']),
            'high': len([e for e in events if e.get('severity') == 'high']),
            'medium': len([e for e in events if e.get('severity') == 'medium']),
            'low': len([e for e in events if e.get('severity') == 'low']),
            'by_type': {}
        }
        
        # Count by event type
        for event in events:
            event_type = event.get('event_type', 'unknown')
            stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1
        
        return stats


if __name__ == '__main__':
    # Test the parser
    parser = FirewallEventParser()
    
    # Test with sample log line
    test_line = "[2025-11-02 15:19:54] server-01 sudo ufw reset"
    print(f"Testing with: {test_line}")
    event = parser.parse_log_line(test_line)
    
    if event:
        print(f"\n Detected event:")
        print(f"  Type: {event.get('event_type')}")
        print(f"  Severity: {event.get('severity')}")
        print(f"  Description: {event.get('description')}")
    else:
        print("\n No event detected")
        print("\nNote: Make sure to build the C parser first:")
        print("  cd firewall && make")

