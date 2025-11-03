#include "../include/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Provide a portable strdup replacement for strict C99 builds
static char* duplicate_string(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

// Simple parser for packet log entries
// Format: YYYY-MM-DD HH:MM:SS | SRC_IP:SRC_PORT -> DST_IP:DST_PORT | PROTOCOL | Size: XXB

ParsedPacket* parse_log_line(const char* line) {
    if (!line) {
        return NULL;
    }
    
    ParsedPacket* packet = (ParsedPacket*)malloc(sizeof(ParsedPacket));
    if (!packet) {
        return NULL;
    }
    
    // Initialize
    packet->timestamp = NULL;
    packet->src_ip = NULL;
    packet->dst_ip = NULL;
    packet->src_port = 0;
    packet->dst_port = 0;
    packet->protocol = NULL;
    packet->size = 0;
    packet->payload = NULL;
    
    char* line_copy = duplicate_string(line);
    if (!line_copy) {
        free(packet);
        return NULL;
    }
    
    // Tokenize by "|"
    char* tokens[10];
    int token_count = 0;
    char* token = strtok(line_copy, "|");
    
    while (token && token_count < 10) {
        // Trim whitespace
        while (*token == ' ' || *token == '\t') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
            *end = '\0';
            end--;
        }
        tokens[token_count++] = token;
        token = strtok(NULL, "|");
    }
    
    if (token_count < 2) {
        // Unknown packet format
        free(line_copy);
        return packet;
    }
    
    // Parse timestamp (first token)
    packet->timestamp = duplicate_string(tokens[0]);
    
    // Check if it's an unknown packet
    if (token_count >= 3 && strstr(tokens[1], "Unknown packet") != NULL) {
        // Extract size from last token
        if (token_count >= 3) {
            char* size_str = tokens[2];
            // Look for "Size: XXB"
            if (strstr(size_str, "Size:") != NULL) {
                char* num_start = strstr(size_str, "Size:") + 5;
                while (*num_start == ' ') num_start++;
                int size = atoi(num_start);
                packet->size = size;
            }
        }
        packet->src_ip = duplicate_string("0.0.0.0");
        packet->dst_ip = duplicate_string("0.0.0.0");
        packet->protocol = duplicate_string("Unknown");
        free(line_copy);
        return packet;
    }
    
    // Parse packet info (second token): SRC_IP:SRC_PORT -> DST_IP:DST_PORT
    if (token_count >= 2) {
        char* info = tokens[1];
        char* arrow = strstr(info, "->");
        
        if (arrow) {
            // Parse source IP:PORT
            *arrow = '\0';
            char* src = info;
            while (*src == ' ') src++;
            
            char* colon = strchr(src, ':');
            if (colon) {
                *colon = '\0';
                packet->src_ip = duplicate_string(src);
                packet->src_port = atoi(colon + 1);
            } else {
                packet->src_ip = duplicate_string(src);
                packet->src_port = 0;
            }
            
            // Parse destination IP:PORT
            char* dst = arrow + 2;
            while (*dst == ' ') dst++;
            
            colon = strchr(dst, ':');
            if (colon) {
                *colon = '\0';
                packet->dst_ip = duplicate_string(dst);
                packet->dst_port = atoi(colon + 1);
            } else {
                packet->dst_ip = duplicate_string(dst);
                packet->dst_port = 0;
            }
        }
    }
    
    // Parse protocol (third token)
    if (token_count >= 3) {
        char* proto = tokens[2];
        while (*proto == ' ') proto++;
        packet->protocol = duplicate_string(proto);
    }
    
    // Parse size (fourth token): Size: XXB
    if (token_count >= 4) {
        char* size_str = tokens[3];
        if (strstr(size_str, "Size:") != NULL) {
            char* num_start = strstr(size_str, "Size:") + 5;
            while (*num_start == ' ') num_start++;
            int size = atoi(num_start);
            packet->size = size;
        }
    }
    
    free(line_copy);
    return packet;
}

void free_parsed_packet(ParsedPacket* packet) {
    if (!packet) return;
    free(packet->timestamp);
    free(packet->src_ip);
    free(packet->dst_ip);
    free(packet->protocol);
    free(packet->payload);
    free(packet);
}

