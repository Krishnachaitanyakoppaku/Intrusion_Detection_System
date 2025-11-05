#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "ast.h"

// Error codes for packet log parsing
typedef enum {
    PKT_ERROR_NONE = 0,
    PKT_ERROR_INVALID_FORMAT,
    PKT_ERROR_INVALID_TIMESTAMP,
    PKT_ERROR_INVALID_IP,
    PKT_ERROR_INVALID_PORT,
    PKT_ERROR_INVALID_PROTOCOL,
    PKT_ERROR_INVALID_SIZE,
    PKT_ERROR_MISSING_SEPARATOR,
    PKT_ERROR_MISSING_ARROW,
    PKT_ERROR_MISSING_COLON
} PacketErrorCode;

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

// Validation functions
int validate_timestamp_format(const char* timestamp);
int validate_ip_address(const char* ip);
int validate_port(int port);
int validate_protocol(const char* protocol);
int validate_size(int size);

// Error tracking
extern PacketErrorCode last_error_code;
extern char last_error_msg[256];
int get_last_packet_error_code(void);
const char* get_last_packet_error_msg(void);

// Function declarations
int parse_packet_log(const char* log_entry);
void init_parsed_packet(void);
ParsedPacket* get_parsed_packet(void);
ParsedPacket* parse_log_line(const char* line);
void free_parsed_packet(ParsedPacket* packet);

#endif // PACKET_PARSER_H

