#ifndef ENGINE_H
#define ENGINE_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <sys/types.h>
#include <stdint.h>

// Define BSD types if not already defined
#ifndef u_char
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#endif

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include "../include/ast.h"

// Engine configuration structure
typedef struct {
    char* interface;      // Network interface to monitor
    char* log_file;       // Log file for alerts
    int promiscuous;      // Promiscuous mode flag
    int timeout;          // Packet capture timeout
} EngineConfig;

// Packet information structure
typedef struct {
    struct timeval timestamp;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t payload_len;
    char* payload;
} PacketInfo;

// Alert structure
typedef struct {
    struct timeval timestamp;
    char* rule_msg;
    char* src_ip;
    char* dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char* content_match;
    int severity;
} Alert;

// Function declarations
int start_engine(Rule* rules, EngineConfig* config);
int stop_engine(void);
int process_packet(const struct pcap_pkthdr* header, const u_char* packet, Rule* rules);
int match_rule(Rule* rule, PacketInfo* packet_info);
int check_content_match(RuleOption* options, char* payload, int payload_len);
int check_ip_match(const char* rule_ip, const char* packet_ip);
int check_port_match(const char* rule_port, uint16_t packet_port);
int check_protocol_match(const char* rule_protocol, uint8_t packet_protocol);
void generate_alert(Alert* alert);
void log_alert(Alert* alert, const char* log_file);
void free_alert(Alert* alert);
void free_packet_info(PacketInfo* packet_info);
int parse_ip_packet(const u_char* packet, int packet_len, PacketInfo* packet_info);
int parse_tcp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info);
int parse_udp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info);
int parse_icmp_packet(const u_char* packet, int packet_len, PacketInfo* packet_info);

// Global variables
extern pcap_t* pcap_handle;
extern int engine_running;

#endif // ENGINE_H
