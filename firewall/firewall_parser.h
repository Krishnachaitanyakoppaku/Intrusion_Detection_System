#ifndef FIREWALL_PARSER_H
#define FIREWALL_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Firewall Event Structure
typedef struct FirewallEvent {
    char* event_type;          // e.g., "ufw_reset", "iptables_flush"
    char* severity;            // "critical", "high", "medium", "low"
    char* description;          // Human-readable description
    char* timestamp;            // Extracted timestamp
    char* source_ip;            // Source IP address
    char* hostname;             // Hostname
    char* command;              // Extracted command
    char* raw_line;             // Original log line
    struct FirewallEvent* next; // Linked list
} FirewallEvent;

// Function declarations
FirewallEvent* parse_firewall_log(const char* log_line);
FirewallEvent* create_firewall_event(const char* event_type, const char* severity, const char* description);
void free_firewall_events(FirewallEvent* events);

// Parser functions
int yyparse(void);
int yylex(void);
void yyerror(const char* msg);

// Global variables
extern int yylineno;
extern char* yytext;
extern FILE* yyin;

#endif /* FIREWALL_PARSER_H */


