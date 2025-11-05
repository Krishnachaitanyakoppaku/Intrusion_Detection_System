#include "../include/packet_parser.h"
#include "../include/rule_matcher.h"
#include "../include/ast.h"
#include "../include/rules_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 1024

int main(int argc, char* argv[]) {
    const char* packet_log_file = "logs/all_packets.log";
    const char* rules_file = "rules/local.rules";
    
    // Parse command line arguments
    if (argc > 1) {
        packet_log_file = argv[1];
    }
    if (argc > 2) {
        rules_file = argv[2];
    }
    
    printf("Packet Analyzer - IDS Rule Matching Engine\n");
    printf("==========================================\n");
    printf("Packet log: %s\n", packet_log_file);
    printf("Rules file: %s\n", rules_file);
    printf("\n");
    
    // Load rules
    printf("Loading rules from %s...\n", rules_file);
    if (parse_rules(rules_file) != 0) {
        fprintf(stderr, "Error: Failed to parse rules file\n");
        return 1;
    }
    
    // Count rules
    int rule_count = 0;
    Rule* current = rule_list;
    while (current) {
        rule_count++;
        current = current->next;
    }
    printf("Loaded %d rules.\n\n", rule_count);
    
    // Open packet log file
    FILE* log_file = fopen(packet_log_file, "r");
    if (!log_file) {
        fprintf(stderr, "Error: Cannot open packet log file: %s\n", packet_log_file);
        return 1;
    }
    
    printf("Analyzing packets from log file...\n");
    printf("===================================\n\n");
    
    char line[MAX_LINE_LENGTH];
    int packet_count = 0;
    int alert_count = 0;
    
    // Read log file line by line
    while (fgets(line, sizeof(line), log_file)) {
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        if (strlen(line) == 0) {
            continue;
        }
        
        // Parse the log line
        ParsedPacket* packet = parse_log_line(line);
        if (!packet) {
            continue;
        }
        
        // Validate parsed packet has required fields
        if (!packet->protocol) {
            free_parsed_packet(packet);
            continue;
        }
        
        packet_count++;
        
        // Match against rules
        if (strcmp(packet->protocol, "Unknown") != 0) {
            match_packet_against_rules(packet, rule_list);
        }
        
        // Free parsed packet
        free_parsed_packet(packet);
        
        // Print progress every 100 packets
        if (packet_count % 100 == 0) {
            printf("Processed %d packets...\r", packet_count);
            fflush(stdout);
        }
    }
    
    fclose(log_file);
    
    printf("\n\nAnalysis complete!\n");
    printf("Processed %d packets.\n", packet_count);
    if (packet_count > 0) {
        printf("Successfully parsed %d packets from log file.\n", packet_count);
    } else {
        printf("No packets found in log file.\n");
    }
    printf("Check logs/alerts.log for generated alerts.\n");
    
    // Cleanup
    free_rule_list(rule_list);
    
    return 0;
}

