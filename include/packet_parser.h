#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "ast.h"

// Parsed packet structure used by the compiler-design packet log parser
// Represents a single line from logs/all_packets.log
typedef struct ParsedPacket {
    char* timestamp;
    char* src_ip;
    int   src_port;
    char* dst_ip;
    int   dst_port;
    char* protocol; // e.g., "TCP", "UDP", "ICMP", "IP", "Unknown"
    int   size;     // bytes
    char* payload;  // optional, may be NULL
} ParsedPacket;

// External variable for parsed packet
extern ParsedPacket* parsed_packet;

// Function declarations
int parse_packet_log(const char* log_entry);
void init_parsed_packet(void);
ParsedPacket* get_parsed_packet(void);
ParsedPacket* parse_log_line(const char* line);
void free_parsed_packet(ParsedPacket* packet);

#endif // PACKET_PARSER_H

