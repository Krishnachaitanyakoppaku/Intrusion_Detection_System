#include "../include/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Error tracking
PacketErrorCode last_error_code = PKT_ERROR_NONE;
char last_error_msg[256] = {0};

// Provide a portable strdup replacement for strict C99 builds
static char* duplicate_string(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

// Validation functions
int validate_timestamp_format(const char* timestamp) {
    if (!timestamp) return 0;
    // Expected format: YYYY-MM-DD HH:MM:SS
    // Check length (should be 19 characters)
    if (strlen(timestamp) < 19) return 0;
    
    // Check format: YYYY-MM-DD HH:MM:SS
    int year, month, day, hour, min, sec;
    if (sscanf(timestamp, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec) != 6) {
        return 0;
    }
    
    // Basic range validation
    if (year < 1900 || year > 3000) return 0;
    if (month < 1 || month > 12) return 0;
    if (day < 1 || day > 31) return 0;
    if (hour < 0 || hour > 23) return 0;
    if (min < 0 || min > 59) return 0;
    if (sec < 0 || sec > 59) return 0;
    
    return 1;
}

int validate_ip_address(const char* ip) {
    if (!ip) return 0;
    
    int octets[4];
    int count = sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    if (count != 4) return 0;
    
    for (int i = 0; i < 4; i++) {
        if (octets[i] < 0 || octets[i] > 255) return 0;
    }
    return 1;
}

int validate_port(int port) {
    return (port >= 0 && port <= 65535);
}

int validate_protocol(const char* protocol) {
    if (!protocol) return 0;
    
    // Check if protocol is one of the valid values
    return (strcmp(protocol, "TCP") == 0 ||
            strcmp(protocol, "UDP") == 0 ||
            strcmp(protocol, "ICMP") == 0 ||
            strcmp(protocol, "IP") == 0 ||
            strcmp(protocol, "Unknown") == 0);
}

int validate_size(int size) {
    return (size >= 0 && size <= 65535);
}

ParsedPacket* parse_log_line(const char* line) {
    // Reset error tracking
    last_error_code = PKT_ERROR_NONE;
    last_error_msg[0] = '\0';
    
    if (!line) {
        last_error_code = PKT_ERROR_INVALID_FORMAT;
        snprintf(last_error_msg, sizeof(last_error_msg), "NULL line input");
        return NULL;
    }
    
    ParsedPacket* packet = (ParsedPacket*)malloc(sizeof(ParsedPacket));
    if (!packet) {
        last_error_code = PKT_ERROR_INVALID_FORMAT;
        snprintf(last_error_msg, sizeof(last_error_msg), "Memory allocation failed");
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
        last_error_code = PKT_ERROR_INVALID_FORMAT;
        snprintf(last_error_msg, sizeof(last_error_msg), "Failed to duplicate line");
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
        last_error_code = PKT_ERROR_MISSING_SEPARATOR;
        snprintf(last_error_msg, sizeof(last_error_msg), "Missing pipe separator (|) or insufficient tokens");
        free(line_copy);
        return packet;
    }
    
    // Parse timestamp (first token)
    packet->timestamp = duplicate_string(tokens[0]);
    
    // Validate timestamp format
    if (!validate_timestamp_format(packet->timestamp)) {
        last_error_code = PKT_ERROR_INVALID_TIMESTAMP;
        snprintf(last_error_msg, sizeof(last_error_msg), "Invalid timestamp format: '%s' (expected: YYYY-MM-DD HH:MM:SS)", packet->timestamp);
        // Continue parsing but mark error
    }
    
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
                if (!validate_size(size)) {
                    last_error_code = PKT_ERROR_INVALID_SIZE;
                    snprintf(last_error_msg, sizeof(last_error_msg), "Invalid packet size: %d (must be 0-65535)", size);
                }
                packet->size = size;
            } else {
                last_error_code = PKT_ERROR_INVALID_SIZE;
                snprintf(last_error_msg, sizeof(last_error_msg), "Missing 'Size:' keyword in unknown packet entry");
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
        
        if (!arrow) {
            last_error_code = PKT_ERROR_MISSING_ARROW;
            snprintf(last_error_msg, sizeof(last_error_msg), "Missing direction arrow (->) in packet info: '%s'", info);
            free(line_copy);
            return packet;
        }
        
        // Parse source IP:PORT
        *arrow = '\0';
        char* src = info;
        while (*src == ' ') src++;
        
        char* colon = strchr(src, ':');
        if (colon) {
            *colon = '\0';
            packet->src_ip = duplicate_string(src);
            packet->src_port = atoi(colon + 1);
            
            // Validate source IP
            if (!validate_ip_address(packet->src_ip)) {
                last_error_code = PKT_ERROR_INVALID_IP;
                snprintf(last_error_msg, sizeof(last_error_msg), "Invalid source IP address: '%s'", packet->src_ip);
            }
            
            // Validate source port
            if (!validate_port(packet->src_port)) {
                last_error_code = PKT_ERROR_INVALID_PORT;
                snprintf(last_error_msg, sizeof(last_error_msg), "Invalid source port: %d (must be 0-65535)", packet->src_port);
            }
        } else {
            last_error_code = PKT_ERROR_INVALID_FORMAT;
            snprintf(last_error_msg, sizeof(last_error_msg), "Missing colon (:) in source IP:PORT");
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
            
            // Validate destination IP
            if (!validate_ip_address(packet->dst_ip)) {
                last_error_code = PKT_ERROR_INVALID_IP;
                snprintf(last_error_msg, sizeof(last_error_msg), "Invalid destination IP address: '%s'", packet->dst_ip);
            }
            
            // Validate destination port
            if (!validate_port(packet->dst_port)) {
                last_error_code = PKT_ERROR_INVALID_PORT;
                snprintf(last_error_msg, sizeof(last_error_msg), "Invalid destination port: %d (must be 0-65535)", packet->dst_port);
            }
        } else {
            last_error_code = PKT_ERROR_INVALID_FORMAT;
            snprintf(last_error_msg, sizeof(last_error_msg), "Missing colon (:) in destination IP:PORT");
            packet->dst_ip = duplicate_string(dst);
            packet->dst_port = 0;
        }
    }
    
    // Parse protocol (third token)
    if (token_count >= 3) {
        char* proto = tokens[2];
        while (*proto == ' ') proto++;
        packet->protocol = duplicate_string(proto);
        
        // Validate protocol
        if (!validate_protocol(packet->protocol)) {
            last_error_code = PKT_ERROR_INVALID_PROTOCOL;
            snprintf(last_error_msg, sizeof(last_error_msg), "Invalid protocol: '%s' (expected: TCP, UDP, ICMP, IP, or Unknown)", packet->protocol);
        }
    } else {
        last_error_code = PKT_ERROR_INVALID_FORMAT;
        snprintf(last_error_msg, sizeof(last_error_msg), "Missing protocol field");
    }
    
    // Parse size (fourth token): Size: XXB
    if (token_count >= 4) {
        char* size_str = tokens[3];
        if (strstr(size_str, "Size:") != NULL) {
            char* num_start = strstr(size_str, "Size:") + 5;
            while (*num_start == ' ') num_start++;
            int size = atoi(num_start);
            
            if (!validate_size(size)) {
                last_error_code = PKT_ERROR_INVALID_SIZE;
                snprintf(last_error_msg, sizeof(last_error_msg), "Invalid packet size: %d (must be 0-65535)", size);
            }
            packet->size = size;
        } else {
            last_error_code = PKT_ERROR_INVALID_SIZE;
            snprintf(last_error_msg, sizeof(last_error_msg), "Missing 'Size:' keyword in size field");
        }
    } else {
        last_error_code = PKT_ERROR_INVALID_FORMAT;
        snprintf(last_error_msg, sizeof(last_error_msg), "Missing size field");
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

