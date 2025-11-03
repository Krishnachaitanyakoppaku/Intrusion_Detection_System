#include "../include/rule_matcher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// Cache the host IP loaded from configuration file
static const char* get_cached_host_ip(void) {
    static int loaded = 0;
    static char host_ip_buf[64];
    if (loaded) {
        return host_ip_buf[0] ? host_ip_buf : NULL;
    }
    loaded = 1;
    host_ip_buf[0] = '\0';
    FILE* f = fopen(".ids_host_ip", "r");
    if (!f) {
        return NULL;
    }
    if (fgets(host_ip_buf, (int)sizeof(host_ip_buf), f) != NULL) {
        // Trim trailing newline and spaces
        size_t n = strlen(host_ip_buf);
        while (n > 0 && (host_ip_buf[n-1] == '\n' || host_ip_buf[n-1] == '\r' || host_ip_buf[n-1] == ' ' || host_ip_buf[n-1] == '\t')) {
            host_ip_buf[--n] = '\0';
        }
    }
    fclose(f);
    return host_ip_buf[0] ? host_ip_buf : NULL;
}

// Helper function to check if IP matches rule (handles "any")
int ip_matches(const char* rule_ip, const char* packet_ip) {
    if (!rule_ip || !packet_ip) {
        return 0;
    }
    
    if (strcmp(rule_ip, "any") == 0) {
        return 1;
    }
    
    return strcmp(rule_ip, packet_ip) == 0;
}

// Helper function to check if port matches rule (handles "any")
int port_matches(const char* rule_port, int packet_port) {
    if (!rule_port) {
        return 0;
    }
    
    if (strcmp(rule_port, "any") == 0) {
        return 1;
    }
    
    int rule_port_num = atoi(rule_port);
    return rule_port_num == packet_port;
}

// Helper function to convert protocol name to lowercase for comparison
void to_lowercase(char* str) {
    if (!str) return;
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

// Check if protocol matches
int protocol_matches(const char* rule_protocol, const char* packet_protocol) {
    if (!rule_protocol || !packet_protocol) {
        return 0;
    }
    
    char rule_proto[10];
    char packet_proto[10];
    
    strncpy(rule_proto, rule_protocol, sizeof(rule_proto) - 1);
    rule_proto[sizeof(rule_proto) - 1] = '\0';
    strncpy(packet_proto, packet_protocol, sizeof(packet_proto) - 1);
    packet_proto[sizeof(packet_proto) - 1] = '\0';
    
    to_lowercase(rule_proto);
    to_lowercase(packet_proto);
    
    return strcmp(rule_proto, packet_proto) == 0;
}

// Check if content matches in packet (simple string search)
int content_matches(const char* content, const char* packet_data) {
    if (!content || !packet_data) {
        return 0;
    }
    
    // Simple substring search
    return strstr(packet_data, content) != NULL;
}

// Check if packet matches a rule
int packet_matches_rule(ParsedPacket* packet, Rule* rule) {
    if (!packet || !rule) {
        return 0;
    }
    
    // Check protocol
    if (!protocol_matches(rule->protocol, packet->protocol)) {
        return 0;
    }
    
    // Enforce incoming-only behavior when host IP is known:
    // If a host IP is configured, only consider packets whose destination IP
    // equals the host IP as "incoming" for alert rules.
    const char* host_ip = get_cached_host_ip();
    if (host_ip && packet->dst_ip && strcmp(packet->dst_ip, host_ip) != 0) {
        return 0;
    }

    // Check direction and IP/port matching
    // For "->" direction: check src and dst
    // For "<>" direction: check either direction
    if (rule->direction && strcmp(rule->direction, "->") == 0) {
        // One-way: source -> destination
        if (!ip_matches(rule->source_ip, packet->src_ip) ||
            !ip_matches(rule->dest_ip, packet->dst_ip)) {
            return 0;
        }
        
        if (!port_matches(rule->source_port, packet->src_port) ||
            !port_matches(rule->dest_port, packet->dst_port)) {
            return 0;
        }
    } else if (rule->direction && strcmp(rule->direction, "<>") == 0) {
        // Bidirectional: check both directions
        int matches_forward = (ip_matches(rule->source_ip, packet->src_ip) &&
                              ip_matches(rule->dest_ip, packet->dst_ip) &&
                              port_matches(rule->source_port, packet->src_port) &&
                              port_matches(rule->dest_port, packet->dst_port));
        
        int matches_reverse = (ip_matches(rule->source_ip, packet->dst_ip) &&
                               ip_matches(rule->dest_ip, packet->src_ip) &&
                               port_matches(rule->source_port, packet->dst_port) &&
                               port_matches(rule->dest_port, packet->src_port));
        
        if (!matches_forward && !matches_reverse) {
            return 0;
        }
    }
    
    // Check content option if present
    const char* content = get_rule_option(rule, "content");
    if (content && packet->payload) {
        if (!content_matches(content, packet->payload)) {
            return 0;
        }
    }
    
    return 1;
}

// Write alert to alerts.log
void write_alert(ParsedPacket* packet, Rule* rule) {
    if (!packet || !rule) {
        return;
    }
    
    FILE* alert_file = fopen("logs/alerts.log", "a");
    if (!alert_file) {
        fprintf(stderr, "Error: Cannot open alerts.log for writing\n");
        return;
    }
    
    // Get message from rule options
    const char* msg = get_rule_option(rule, "msg");
    if (!msg) {
        msg = "Intrusion detected";
    }
    
    // Get priority from rule options
    const char* priority_str = get_rule_option(rule, "priority");
    int priority = 5; // Default priority
    if (priority_str) {
        priority = atoi(priority_str);
    }
    
    // Format: [YYYY-MM-DD HH:MM:SS] ALERT: MESSAGE | SRC_IP:SRC_PORT -> DST_IP:DST_PORT | Protocol: PROTOCOL | Priority: X
    char timestamp[64];
    if (packet->timestamp) {
        strncpy(timestamp, packet->timestamp, sizeof(timestamp) - 1);
        timestamp[sizeof(timestamp) - 1] = '\0';
    } else {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    }
    
    fprintf(alert_file, "[%s] ALERT: %s | %s:%d -> %s:%d | Protocol: %s | Priority: %d\n",
            timestamp,
            msg,
            packet->src_ip ? packet->src_ip : "0.0.0.0",
            packet->src_port,
            packet->dst_ip ? packet->dst_ip : "0.0.0.0",
            packet->dst_port,
            packet->protocol ? packet->protocol : "Unknown",
            priority);
    
    fclose(alert_file);
}

// Match packet against all rules
void match_packet_against_rules(ParsedPacket* packet, Rule* rule_list) {
    if (!packet || !rule_list) {
        return;
    }
    
    Rule* current = rule_list;
    while (current) {
        // Only process "alert" rules (skip "log" and "pass" for now)
        if (current->action && strcmp(current->action, "alert") == 0) {
            if (packet_matches_rule(packet, current)) {
                write_alert(packet, current);
            }
        }
        current = current->next;
    }
}

