#ifndef AST_H
#define AST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Rule option structure (linked list of options)
typedef struct RuleOption {
    char* name;
    char* value;
    struct RuleOption* next;
} RuleOption;

// Rule structure (linked list of rules)
typedef struct Rule {
    char* action;        // alert, log, pass
    char* protocol;      // tcp, udp, icmp, ip
    char* source_ip;
    char* source_port;
    char* direction;     // -> or <>
    char* dest_ip;
    char* dest_port;
    RuleOption* options; // Linked list of rule options
    struct Rule* next;   // Next rule in list
} Rule;

// Function declarations
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
