%code requires {
#define _GNU_SOURCE
#include "../include/packet_parser.h"
}

%{
#include "../include/packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Provide a portable strdup replacement for strict C99 builds
static char* duplicate_string(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}
#define strdup duplicate_string

// External variables
extern int yylineno;
extern char* yytext;
extern FILE* yyin;

// Function declarations
int yylex(void);
void yyerror(const char* msg);
%}

%union {
    int number;
    char* string;
}

%token <string> DATE TIME IP_ADDRESS PROTOCOL WORD
%token <number> NUMBER
%token ARROW PIPE COLON SIZE_KEYWORD UNKNOWN_PACKET NEWLINE

%define api.prefix {pkt}

%type <string> timestamp ip_port_pair protocol_type

%%

packet_entry:
    timestamp PIPE packet_info NEWLINE
    {
        // Packet successfully parsed
    }
    | timestamp PIPE UNKNOWN_PACKET PIPE SIZE_KEYWORD NUMBER WORD NEWLINE
    {
        // Unknown packet format
        if (parsed_packet) {
            parsed_packet->src_ip = strdup("0.0.0.0");
            parsed_packet->dst_ip = strdup("0.0.0.0");
            parsed_packet->src_port = 0;
            parsed_packet->dst_port = 0;
            parsed_packet->protocol = strdup("Unknown");
            parsed_packet->size = $6;
        }
    }
    ;

timestamp:
    DATE TIME
    {
        // Combine date and time
        if (parsed_packet) {
            int len = strlen($1) + strlen($2) + 2;
            parsed_packet->timestamp = (char*)malloc(len);
            sprintf(parsed_packet->timestamp, "%s %s", $1, $2);
            free($1);
            free($2);
        }
    }
    ;

packet_info:
    src_ip_port ARROW dst_ip_port PIPE protocol_type PIPE SIZE_KEYWORD NUMBER WORD
    {
        if (parsed_packet) {
            parsed_packet->size = $9;
        }
    }
    ;

src_ip_port:
    IP_ADDRESS COLON NUMBER
    {
        if (parsed_packet) {
            parsed_packet->src_ip = $1;
            parsed_packet->src_port = $3;
        }
    }
    ;

dst_ip_port:
    IP_ADDRESS COLON NUMBER
    {
        if (parsed_packet) {
            parsed_packet->dst_ip = $1;
            parsed_packet->dst_port = $3;
        }
    }
    ;

protocol_type:
    PROTOCOL
    {
        if (parsed_packet) {
            parsed_packet->protocol = $1;
        }
    }
    ;

%%

// Global parsed packet structure
ParsedPacket* parsed_packet = NULL;

// Error handling function with enhanced error messages
void yyerror(const char* msg) {
    fprintf(stderr, "ERROR: Packet log parse error at line %d: %s\n", yylineno, msg);
    if (yytext && strlen(yytext) > 0) {
        fprintf(stderr, "       Unexpected token near: '%s'\n", yytext);
    }
    fprintf(stderr, "       Expected format: YYYY-MM-DD HH:MM:SS | SRC_IP:SRC_PORT -> DST_IP:DST_PORT | PROTOCOL | Size: XXB\n");
}

// Initialize parsed packet
void init_parsed_packet(void) {
    if (parsed_packet) {
        free_parsed_packet(parsed_packet);
    }
    parsed_packet = (ParsedPacket*)malloc(sizeof(ParsedPacket));
    if (parsed_packet) {
        parsed_packet->timestamp = NULL;
        parsed_packet->src_ip = NULL;
        parsed_packet->dst_ip = NULL;
        parsed_packet->src_port = 0;
        parsed_packet->dst_port = 0;
        parsed_packet->protocol = NULL;
        parsed_packet->size = 0;
        parsed_packet->payload = NULL;
    }
}

// Get parsed packet
ParsedPacket* get_parsed_packet(void) {
    return parsed_packet;
}

// Parse a single log entry (simplified version)
// Note: This is a helper function that uses a modified parser
int parse_packet_log_line(const char* log_line) {
    // This function will be implemented to parse one line at a time
    // For now, we'll use a simpler parsing approach
    return 0;
}

// Main parsing function for packet log file
int parse_packet_log(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 1;
    }
    
    yyin = file;
    
    init_parsed_packet();
    int result = yyparse();
    
    fclose(file);
    return result;
}

