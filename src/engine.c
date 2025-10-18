#include "../include/engine.h"
#include <string.h>
#include <signal.h>
#include <errno.h>

// Global variables
pcap_t* pcap_handle = NULL;
int engine_running = 0;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nShutting down IDS engine...\n");
        engine_running = 0;
    }
}

// Start the IDS engine
int start_engine(Rule* rules, EngineConfig* config) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";  // Basic IP filter
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Open the network interface
    pcap_handle = pcap_open_live(config->interface, BUFSIZ, config->promiscuous, 
                                 config->timeout, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", config->interface, errbuf);
        return 1;
    }
    
    // Compile and set the filter
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return 1;
    }
    
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(pcap_handle));
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        return 1;
    }
    
    pcap_freecode(&fp);
    
    printf("IDS Engine started on interface %s\n", config->interface);
    printf("Monitoring for threats...\n");
    
    engine_running = 1;
    
    // Start packet capture loop
    pcap_loop(pcap_handle, -1, (pcap_handler)process_packet, (u_char*)rules);
    
    return 0;
}

// Stop the IDS engine
int stop_engine(void) {
    engine_running = 0;
    if (pcap_handle) {
        pcap_breakloop(pcap_handle);
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
    return 0;
}

// Process captured packets
int process_packet(const struct pcap_pkthdr* header, const u_char* packet, Rule* rules) {
    if (!engine_running) {
        return 0;
    }
    
    PacketInfo packet_info;
    memset(&packet_info, 0, sizeof(PacketInfo));
    
    // Parse the packet
    if (parse_ip_packet(packet, header->caplen, &packet_info) != 0) {
        return 0;
    }
    
    // Check against all rules
    Rule* current_rule = rules;
    while (current_rule) {
        if (match_rule(current_rule, &packet_info)) {
            // Create and log alert
            Alert alert;
            memset(&alert, 0, sizeof(Alert));
            alert.timestamp = header->ts;
            strcpy(alert.src_ip, packet_info.src_ip);
            strcpy(alert.dst_ip, packet_info.dst_ip);
            alert.src_port = packet_info.src_port;
            alert.dst_port = packet_info.dst_port;
            alert.protocol = packet_info.protocol;
            
            // Get rule message
            RuleOption* option = current_rule->options;
            while (option) {
                if (strcmp(option->name, "msg") == 0) {
                    alert.rule_msg = strdup(option->value);
                    break;
                }
                option = option->next;
            }
            
            // Get priority/severity
            option = current_rule->options;
            while (option) {
                if (strcmp(option->name, "priority") == 0) {
                    alert.severity = atoi(option->value);
                    break;
                }
                option = option->next;
            }
            
            generate_alert(&alert);
            free_alert(&alert);
        }
        current_rule = current_rule->next;
    }
    
    free_packet_info(&packet_info);
    return 0;
}

// Match a packet against a rule
int match_rule(Rule* rule, PacketInfo* packet_info) {
    if (!rule || !packet_info) {
        return 0;
    }
    
    // Check protocol match
    if (!check_protocol_match(rule->protocol, packet_info->protocol)) {
        return 0;
    }
    
    // Check IP address matches
    if (!check_ip_match(rule->source_ip, packet_info->src_ip) ||
        !check_ip_match(rule->dest_ip, packet_info->dst_ip)) {
        return 0;
    }
    
    // Check port matches
    if (!check_port_match(rule->source_port, packet_info->src_port) ||
        !check_port_match(rule->dest_port, packet_info->dst_port)) {
        return 0;
    }
    
    // Check content matches
    if (packet_info->payload && packet_info->payload_len > 0) {
        if (!check_content_match(rule->options, packet_info->payload, packet_info->payload_len)) {
            return 0;
        }
    }
    
    return 1;
}

// Check content match in rule options
int check_content_match(RuleOption* options, char* payload, int payload_len) {
    RuleOption* option = options;
    while (option) {
        if (strcmp(option->name, "content") == 0) {
            if (strstr(payload, option->value) != NULL) {
                return 1;
            }
        }
        option = option->next;
    }
    return 1; // No content option means match
}

// Check IP address match
int check_ip_match(const char* rule_ip, const char* packet_ip) {
    if (!rule_ip || !packet_ip) {
        return 0;
    }
    
    if (strcmp(rule_ip, "any") == 0) {
        return 1;
    }
    
    return strcmp(rule_ip, packet_ip) == 0;
}

// Check port match
int check_port_match(const char* rule_port, uint16_t packet_port) {
    if (!rule_port) {
        return 0;
    }
    
    if (strcmp(rule_port, "any") == 0) {
        return 1;
    }
    
    int rule_port_num = atoi(rule_port);
    return rule_port_num == packet_port;
}

// Check protocol match
int check_protocol_match(const char* rule_protocol, uint8_t packet_protocol) {
    if (!rule_protocol) {
        return 0;
    }
    
    if (strcmp(rule_protocol, "ip") == 0) {
        return 1; // IP matches all
    }
    
    if (strcmp(rule_protocol, "tcp") == 0) {
        return packet_protocol == IPPROTO_TCP;
    }
    
    if (strcmp(rule_protocol, "udp") == 0) {
        return packet_protocol == IPPROTO_UDP;
    }
    
    if (strcmp(rule_protocol, "icmp") == 0) {
        return packet_protocol == IPPROTO_ICMP;
    }
    
    return 0;
}

// Generate an alert
void generate_alert(Alert* alert) {
    if (!alert) {
        return;
    }
    
    printf("ALERT: %s\n", alert->rule_msg ? alert->rule_msg : "Unknown threat");
    printf("  Source: %s:%d\n", alert->src_ip, alert->src_port);
    printf("  Destination: %s:%d\n", alert->dst_ip, alert->dst_port);
    printf("  Protocol: %d\n", alert->protocol);
    printf("  Severity: %d\n", alert->severity);
    printf("  Time: %ld.%06ld\n", alert->timestamp.tv_sec, alert->timestamp.tv_usec);
    printf("  ---\n");
    
    // Log to file
    log_alert(alert, "logs/alerts.log");
}

// Log alert to file
void log_alert(Alert* alert, const char* log_file) {
    FILE* file = fopen(log_file, "a");
    if (!file) {
        return;
    }
    
    fprintf(file, "[%ld.%06ld] ALERT: %s\n", 
            alert->timestamp.tv_sec, alert->timestamp.tv_usec,
            alert->rule_msg ? alert->rule_msg : "Unknown threat");
    fprintf(file, "  Source: %s:%d -> Destination: %s:%d\n",
            alert->src_ip, alert->src_port, alert->dst_ip, alert->dst_port);
    fprintf(file, "  Protocol: %d, Severity: %d\n", alert->protocol, alert->severity);
    fprintf(file, "  ---\n");
    
    fclose(file);
}

// Free alert memory
void free_alert(Alert* alert) {
    if (alert && alert->rule_msg) {
        free(alert->rule_msg);
    }
    if (alert && alert->content_match) {
        free(alert->content_match);
    }
}

// Free packet info memory
void free_packet_info(PacketInfo* packet_info) {
    if (packet_info && packet_info->payload) {
        free(packet_info->payload);
    }
}

// Parse IP packet
int parse_ip_packet(const u_char* packet, int packet_len, PacketInfo* packet_info) {
    if (packet_len < sizeof(struct ip)) {
        return -1;
    }
    
    struct ip* ip_header = (struct ip*)(packet);
    packet_info->protocol = ip_header->ip_p;
    
    // Convert IP addresses to strings
    inet_ntop(AF_INET, &ip_header->ip_src, packet_info->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, packet_info->dst_ip, INET_ADDRSTRLEN);
    
    // Parse protocol-specific headers
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char* payload = packet + ip_header_len;
    int payload_len = packet_len - ip_header_len;
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            parse_tcp_packet(payload, payload_len, packet_info);
            break;
        case IPPROTO_UDP:
            parse_udp_packet(payload, payload_len, packet_info);
            break;
        case IPPROTO_ICMP:
            parse_icmp_packet(payload, payload_len, packet_info);
            break;
    }
    
    // Store payload
    if (payload_len > 0) {
        packet_info->payload_len = payload_len;
        packet_info->payload = malloc(payload_len);
        memcpy(packet_info->payload, payload, payload_len);
    }
    
    return 0;
}

// Parse TCP packet
int parse_tcp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info) {
    if (packet_len < sizeof(struct tcphdr)) {
        return -1;
    }
    
    struct tcphdr* tcp_header = (struct tcphdr*)packet;
    packet_info->src_port = ntohs(tcp_header->th_sport);
    packet_info->dst_port = ntohs(tcp_header->th_dport);
    
    return 0;
}

// Parse UDP packet
int parse_udp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info) {
    if (packet_len < sizeof(struct udphdr)) {
        return -1;
    }
    
    struct udphdr* udp_header = (struct udphdr*)packet;
    packet_info->src_port = ntohs(udp_header->uh_sport);
    packet_info->dst_port = ntohs(udp_header->uh_dport);
    
    return 0;
}

// Parse ICMP packet
int parse_icmp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info) {
    if (packet_len < sizeof(struct icmp)) {
        return -1;
    }
    
    // ICMP doesn't have ports, set to 0
    packet_info->src_port = 0;
    packet_info->dst_port = 0;
    
    return 0;
}


