#ifndef AST_H
#define AST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations
typedef struct RuleOption RuleOption;
typedef struct Rule Rule;

// Structure to represent a rule option (like msg, content, etc.)
struct RuleOption {
    char* name;           // Option name (e.g., "msg", "content")
    char* value;          // Option value
    RuleOption* next;     // Pointer to next option in the list
};

// Structure to represent a complete rule
struct Rule {
    char* action;         // Rule action (e.g., "alert", "log")
    char* protocol;       // Protocol (e.g., "tcp", "udp", "icmp")
    char* source_ip;      // Source IP address
    char* source_port;    // Source port
    char* direction;      // Direction operator (e.g., "->", "<>")
    char* dest_ip;        // Destination IP address
    char* dest_port;      // Destination port
    RuleOption* options;  // Linked list of rule options
    Rule* next;           // Pointer to next rule in the list
};

// Function declarations for AST management
Rule* create_rule(const char* action, const char* protocol, 
                  const char* source_ip, const char* source_port,
                  const char* direction, const char* dest_ip, const char* dest_port);
RuleOption* create_rule_option(const char* name, const char* value);
void add_option_to_rule(Rule* rule, const char* name, const char* value);
void add_rule_to_list(Rule** rule_list, Rule* new_rule);
void free_rule_option(RuleOption* option);
void free_rule(Rule* rule);
void free_rule_list(Rule* rule_list);
void print_rule(Rule* rule);
void print_rule_list(Rule* rule_list);

#endif // AST_H


