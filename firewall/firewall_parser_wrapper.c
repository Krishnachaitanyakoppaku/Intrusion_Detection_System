/*
 * Firewall Parser Wrapper
 * Provides functions to parse firewall logs from Python or other languages
 */

#define _GNU_SOURCE
#include "firewall_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Export functions for Python ctypes
#ifndef __cplusplus
__attribute__((visibility("default")))
#endif

// Parse a single log line and return JSON-like string representation
char* parse_log_line_to_json(const char* log_line) {
    FirewallEvent* events = parse_firewall_log(log_line);
    
    if (!events) {
        return strdup("[]");
    }
    
    // Build JSON array of events
    char* json = malloc(4096);
    if (!json) return NULL;
    
    strcpy(json, "[");
    FirewallEvent* current = events;
    int first = 1;
    
    while (current) {
        if (!first) strcat(json, ",");
        first = 0;
        
        char event_json[1024];
        snprintf(event_json, sizeof(event_json),
            "{\"event_type\":\"%s\",\"severity\":\"%s\",\"description\":\"%s\""
            "%s%s%s%s%s}",
            current->event_type ? current->event_type : "",
            current->severity ? current->severity : "",
            current->description ? current->description : "",
            current->timestamp ? ",\"timestamp\":\"" : "",
            current->timestamp ? current->timestamp : "",
            current->timestamp ? "\"" : "",
            current->source_ip ? ",\"source_ip\":\"" : "",
            current->source_ip ? current->source_ip : "",
            current->source_ip ? "\"" : ""
        );
        
        if (strlen(json) + strlen(event_json) < 4095) {
            strcat(json, event_json);
        }
        
        current = current->next;
    }
    
    strcat(json, "]");
    
    // Free events
    free_firewall_events(events);
    
    return json;
}

// Parse multiple log lines (file or buffer)
char* parse_log_buffer_to_json(const char* buffer, size_t buffer_size) {
    // Simple implementation - parse line by line
    char* result = malloc(16384);
    if (!result) return NULL;
    
    strcpy(result, "[");
    
    char* buffer_copy = malloc(buffer_size + 1);
    if (!buffer_copy) {
        free(result);
        return NULL;
    }
    memcpy(buffer_copy, buffer, buffer_size);
    buffer_copy[buffer_size] = '\0';
    
    char* line = strtok(buffer_copy, "\n");
    int first = 1;
    
    while (line) {
        FirewallEvent* events = parse_firewall_log(line);
        
        if (events) {
            FirewallEvent* current = events;
            while (current) {
                if (!first) strcat(result, ",");
                first = 0;
                
                char event_json[1024];
                snprintf(event_json, sizeof(event_json),
                    "{\"event_type\":\"%s\",\"severity\":\"%s\",\"description\":\"%s\""
                    "%s%s%s%s%s%s%s}",
                    current->event_type ? current->event_type : "",
                    current->severity ? current->severity : "",
                    current->description ? current->description : "",
                    current->timestamp ? ",\"timestamp\":\"" : "",
                    current->timestamp ? current->timestamp : "",
                    current->timestamp ? "\"" : "",
                    current->source_ip ? ",\"source_ip\":\"" : "",
                    current->source_ip ? current->source_ip : "",
                    current->source_ip ? "\"" : "",
                    current->hostname ? ",\"hostname\":\"" : "",
                    current->hostname ? current->hostname : "",
                    current->hostname ? "\"" : ""
                );
                
                if (strlen(result) + strlen(event_json) < 16383) {
                    strcat(result, event_json);
                }
                
                current = current->next;
            }
            
            free_firewall_events(events);
        }
        
        line = strtok(NULL, "\n");
    }
    
    free(buffer_copy);
    strcat(result, "]");
    
    return result;
}

