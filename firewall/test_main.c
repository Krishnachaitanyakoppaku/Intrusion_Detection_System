/*
 * Test main for firewall parser
 */

#include "firewall_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <log_line>\n", argv[0]);
        printf("Example: %s \"[2025-11-02 15:19:54] server sudo ufw reset\"\n", argv[0]);
        return 1;
    }
    
    const char* log_line = argv[1];
    printf("Parsing log line: %s\n\n", log_line);
    
    FirewallEvent* events = parse_firewall_log(log_line);
    
    if (!events) {
        printf("No firewall events detected.\n");
        return 0;
    }
    
    printf("Detected firewall events:\n");
    printf("========================\n\n");
    
    FirewallEvent* current = events;
    int count = 0;
    
    while (current) {
        count++;
        printf("Event #%d:\n", count);
        printf("  Type:        %s\n", current->event_type ? current->event_type : "N/A");
        printf("  Severity:    %s\n", current->severity ? current->severity : "N/A");
        printf("  Description: %s\n", current->description ? current->description : "N/A");
        if (current->timestamp) {
            printf("  Timestamp:   %s\n", current->timestamp);
        }
        if (current->hostname) {
            printf("  Hostname:    %s\n", current->hostname);
        }
        if (current->source_ip) {
            printf("  Source IP:   %s\n", current->source_ip);
        }
        if (current->command) {
            printf("  Command:     %s\n", current->command);
        }
        printf("\n");
        
        current = current->next;
    }
    
    printf("Total events detected: %d\n", count);
    
    // Free events
    free_firewall_events(events);
    
    return 0;
}


