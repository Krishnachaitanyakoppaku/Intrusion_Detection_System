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
#include <strings.h>

// Helper function to escape JSON string
static void json_escape_string(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) {
        if (output && output_size > 0) output[0] = '\0';
        return;
    }
    
    // Initialize output buffer
    memset(output, 0, output_size);
    
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < output_size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        switch (c) {
            case '"': 
                if (j + 2 < output_size) { output[j++] = '\\'; output[j++] = '"'; }
                break;
            case '\\': 
                if (j + 2 < output_size) { output[j++] = '\\'; output[j++] = '\\'; }
                break;
            case '\n': 
                if (j + 2 < output_size) { output[j++] = '\\'; output[j++] = 'n'; }
                break;
            case '\r': 
                if (j + 2 < output_size) { output[j++] = '\\'; output[j++] = 'r'; }
                break;
            case '\t': 
                if (j + 2 < output_size) { output[j++] = '\\'; output[j++] = 't'; }
                break;
            default:
                // Only include printable ASCII characters
                if (c >= 0x20 && c <= 0x7E) {
                    if (j < output_size - 1) {
                        output[j++] = c;
                    }
                }
                // Skip non-printable and non-ASCII characters
                break;
        }
    }
    output[j] = '\0';
}

// Export functions for Python ctypes
#ifndef __cplusplus
__attribute__((visibility("default")))
#endif

// Parse a single log line and return JSON-like string representation
char* parse_log_line_to_json(const char* log_line) {
    if (!log_line) {
        return strdup("[]");
    }
    FirewallEvent* events = parse_firewall_log(log_line);
    
    if (!events) {
        return strdup("[]");
    }
    
    // Build JSON array of events
    char* json = malloc(16384);
    if (!json) {
        free_firewall_events(events);
        return strdup("[]");
    }
    
    strcpy(json, "[");
    FirewallEvent* current = events;
    int first = 1;
    
    while (current) {
        if (!first) strcat(json, ",");
        first = 0;
        
        // Escape strings for JSON
        char escaped_event_type[256] = "";
        char escaped_severity[256] = "";
        char escaped_description[512] = "";
        char escaped_timestamp[256] = "";
        char escaped_source_ip[256] = "";
        char escaped_hostname[256] = "";
        char escaped_command[512] = "";
        char escaped_raw_line[1024] = "";
        
        if (current->event_type) json_escape_string(current->event_type, escaped_event_type, sizeof(escaped_event_type));
        if (current->severity) json_escape_string(current->severity, escaped_severity, sizeof(escaped_severity));
        if (current->description) json_escape_string(current->description, escaped_description, sizeof(escaped_description));
        if (current->timestamp) json_escape_string(current->timestamp, escaped_timestamp, sizeof(escaped_timestamp));
        if (current->source_ip) json_escape_string(current->source_ip, escaped_source_ip, sizeof(escaped_source_ip));
        if (current->hostname) json_escape_string(current->hostname, escaped_hostname, sizeof(escaped_hostname));
        if (current->command) json_escape_string(current->command, escaped_command, sizeof(escaped_command));
        // Always use the original log_line parameter instead of raw_line to avoid corruption
        json_escape_string(log_line ? log_line : "", escaped_raw_line, sizeof(escaped_raw_line));
        
        char event_json[4096];
        // Build JSON manually to avoid format string issues
        strcpy(event_json, "{\"event_type\":\"");
        strcat(event_json, escaped_event_type);
        strcat(event_json, "\",\"severity\":\"");
        strcat(event_json, escaped_severity);
        strcat(event_json, "\",\"description\":\"");
        strcat(event_json, escaped_description);
        strcat(event_json, "\"");
        
        if (current->timestamp) {
            strcat(event_json, ",\"timestamp\":\"");
            strcat(event_json, escaped_timestamp);
            strcat(event_json, "\"");
        }
        if (current->source_ip) {
            strcat(event_json, ",\"source_ip\":\"");
            strcat(event_json, escaped_source_ip);
            strcat(event_json, "\"");
        }
        if (current->hostname) {
            strcat(event_json, ",\"hostname\":\"");
            strcat(event_json, escaped_hostname);
            strcat(event_json, "\"");
        }
        if (current->command) {
            strcat(event_json, ",\"command\":\"");
            strcat(event_json, escaped_command);
            strcat(event_json, "\"");
        }
        strcat(event_json, ",\"raw_line\":\"");
        strcat(event_json, escaped_raw_line);
        strcat(event_json, "\"}");
        
        int written = strlen(event_json);
        
        // Ensure null termination
        if (written >= (int)sizeof(event_json)) {
            event_json[sizeof(event_json) - 1] = '\0';
        }
        
        // Check available space before concatenating
        size_t json_len = strlen(json);
        size_t event_len = strlen(event_json);
        if (json_len + event_len + 1 < 16384) {
            strncat(json, event_json, 16384 - json_len - 1);
            json[16383] = '\0'; // Ensure null termination
        } else {
            break; // Buffer full
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
    char* result = malloc(65536);
    if (!result) return strdup("[]");
    
    strcpy(result, "[");
    
    char* buffer_copy = malloc(buffer_size + 1);
    if (!buffer_copy) {
        free(result);
        return strdup("[]");
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
                
                // Escape strings for JSON
                char escaped_event_type[256] = "";
                char escaped_severity[256] = "";
                char escaped_description[512] = "";
                char escaped_timestamp[256] = "";
                char escaped_source_ip[256] = "";
                char escaped_hostname[256] = "";
                char escaped_command[512] = "";
                char escaped_raw_line[1024] = "";
                
                if (current->event_type) json_escape_string(current->event_type, escaped_event_type, sizeof(escaped_event_type));
                if (current->severity) json_escape_string(current->severity, escaped_severity, sizeof(escaped_severity));
                if (current->description) json_escape_string(current->description, escaped_description, sizeof(escaped_description));
                if (current->timestamp) json_escape_string(current->timestamp, escaped_timestamp, sizeof(escaped_timestamp));
                if (current->source_ip) json_escape_string(current->source_ip, escaped_source_ip, sizeof(escaped_source_ip));
                if (current->hostname) json_escape_string(current->hostname, escaped_hostname, sizeof(escaped_hostname));
                if (current->command) json_escape_string(current->command, escaped_command, sizeof(escaped_command));
                // Always use the original log line instead of raw_line to avoid corruption
                json_escape_string(line ? line : "", escaped_raw_line, sizeof(escaped_raw_line));
                
                char event_json[4096];
                // Build JSON manually to avoid format string issues
                strcpy(event_json, "{\"event_type\":\"");
                strcat(event_json, escaped_event_type);
                strcat(event_json, "\",\"severity\":\"");
                strcat(event_json, escaped_severity);
                strcat(event_json, "\",\"description\":\"");
                strcat(event_json, escaped_description);
                strcat(event_json, "\"");
                
                if (current->timestamp) {
                    strcat(event_json, ",\"timestamp\":\"");
                    strcat(event_json, escaped_timestamp);
                    strcat(event_json, "\"");
                }
                if (current->source_ip) {
                    strcat(event_json, ",\"source_ip\":\"");
                    strcat(event_json, escaped_source_ip);
                    strcat(event_json, "\"");
                }
                if (current->hostname) {
                    strcat(event_json, ",\"hostname\":\"");
                    strcat(event_json, escaped_hostname);
                    strcat(event_json, "\"");
                }
                if (current->command) {
                    strcat(event_json, ",\"command\":\"");
                    strcat(event_json, escaped_command);
                    strcat(event_json, "\"");
                }
                strcat(event_json, ",\"raw_line\":\"");
                strcat(event_json, escaped_raw_line);
                strcat(event_json, "\"}");
                
                if (strlen(result) + strlen(event_json) < 65535) {
                    strcat(result, event_json);
                } else {
                    break; // Buffer full
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
