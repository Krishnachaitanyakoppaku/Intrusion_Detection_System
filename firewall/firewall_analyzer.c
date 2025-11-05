/*
 * Firewall Analyzer
 * Standalone binary to analyze firewall.log files
 * Similar to bin/packet_analyzer for IDS engine
 */

#include "firewall_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// External declarations for parser functions
extern FirewallEvent* parse_firewall_log(const char* log_line);
extern void free_firewall_events(FirewallEvent* events);

#define MAX_LINE_LENGTH 4096

int main(int argc, char* argv[]) {
    const char* firewall_log_file = "firewall/logs/firewall.log";
    
    if (argc > 1) {
        firewall_log_file = argv[1];
    }
    
    printf("Firewall Analyzer - Parsing firewall logs\n");
    printf("==========================================\n\n");
    printf("Log file: %s\n\n", firewall_log_file);
    
    // Open firewall log file
    FILE* log_fp = fopen(firewall_log_file, "r");
    if (!log_fp) {
        fprintf(stderr, "Error: Cannot open firewall log file %s\n", firewall_log_file);
        return 1;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int total_events = 0;
    
    while (fgets(line, sizeof(line), log_fp)) {
        line_num++;
        
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        if (!line[0] || line[0] == '#') {
            continue; // Skip empty lines and comments
        }
        
        // Parse the log line
        FirewallEvent* events = parse_firewall_log(line);
        
        if (events) {
            FirewallEvent* current = events;
            while (current) {
                total_events++;
                printf("Event #%d (Line %d):\n", total_events, line_num);
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
                printf("  Raw Line:    %s\n", current->raw_line ? current->raw_line : line);
                printf("\n");
                
                current = current->next;
            }
            
            // Free events
            free_firewall_events(events);
        }
    }
    
    fclose(log_fp);
    
    printf("==========================================\n");
    printf("Analysis complete.\n");
    printf("Total events detected: %d\n", total_events);
    
    if (total_events == 0) {
        printf("\nNo firewall events detected. Make sure the log file contains 'sudo ufw reset' commands.\n");
        return 1;
    }
    
    return 0;
}

