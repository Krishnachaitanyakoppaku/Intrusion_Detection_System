#define _GNU_SOURCE
#include "../include/ast.h"
#include "../include/parser.h"

// Create a new rule
Rule* create_rule(const char* action, const char* protocol, 
                  const char* source_ip, const char* source_port,
                  const char* direction, const char* dest_ip, const char* dest_port) {
    Rule* rule = (Rule*)malloc(sizeof(Rule));
    if (!rule) {
        fprintf(stderr, "Error: Failed to allocate memory for rule\n");
        return NULL;
    }
    
    // Initialize all fields
    rule->action = action ? strdup(action) : NULL;
    rule->protocol = protocol ? strdup(protocol) : NULL;
    rule->source_ip = source_ip ? strdup(source_ip) : NULL;
    rule->source_port = source_port ? strdup(source_port) : NULL;
    rule->direction = direction ? strdup(direction) : NULL;
    rule->dest_ip = dest_ip ? strdup(dest_ip) : NULL;
    rule->dest_port = dest_port ? strdup(dest_port) : NULL;
    rule->options = NULL;
    rule->next = NULL;
    
    return rule;
}

// Create a new rule option
RuleOption* create_rule_option(const char* name, const char* value) {
    RuleOption* option = (RuleOption*)malloc(sizeof(RuleOption));
    if (!option) {
        fprintf(stderr, "Error: Failed to allocate memory for rule option\n");
        return NULL;
    }
    
    option->name = name ? strdup(name) : NULL;
    option->value = value ? strdup(value) : NULL;
    option->next = NULL;
    
    return option;
}

// Add an option to a rule
void add_option_to_rule(Rule* rule, const char* name, const char* value) {
    if (!rule || !name || !value) {
        return;
    }
    
    RuleOption* new_option = create_rule_option(name, value);
    if (!new_option) {
        return;
    }
    
    // Add to the beginning of the options list
    new_option->next = rule->options;
    rule->options = new_option;
}

// Add a rule to the rule list
void add_rule_to_list(Rule** rule_list, Rule* new_rule) {
    if (!new_rule) {
        return;
    }
    
    // Add to the beginning of the list
    new_rule->next = *rule_list;
    *rule_list = new_rule;
}

// Free a rule option
void free_rule_option(RuleOption* option) {
    if (!option) {
        return;
    }
    
    free(option->name);
    free(option->value);
    free(option);
}

// Free a rule and all its options
void free_rule(Rule* rule) {
    if (!rule) {
        return;
    }
    
    // Free all options
    RuleOption* current_option = rule->options;
    while (current_option) {
        RuleOption* next_option = current_option->next;
        free_rule_option(current_option);
        current_option = next_option;
    }
    
    // Free rule fields
    free(rule->action);
    free(rule->protocol);
    free(rule->source_ip);
    free(rule->source_port);
    free(rule->direction);
    free(rule->dest_ip);
    free(rule->dest_port);
    free(rule);
}

// Free the entire rule list
void free_rule_list(Rule* rule_list) {
    Rule* current = rule_list;
    while (current) {
        Rule* next = current->next;
        free_rule(current);
        current = next;
    }
}

// Print a single rule
void print_rule(Rule* rule) {
    if (!rule) {
        printf("NULL rule\n");
        return;
    }
    
    printf("Rule: %s %s %s %s %s %s %s\n", 
           rule->action ? rule->action : "NULL",
           rule->protocol ? rule->protocol : "NULL",
           rule->source_ip ? rule->source_ip : "NULL",
           rule->source_port ? rule->source_port : "NULL",
           rule->direction ? rule->direction : "NULL",
           rule->dest_ip ? rule->dest_ip : "NULL",
           rule->dest_port ? rule->dest_port : "NULL");
    
    // Print options
    RuleOption* option = rule->options;
    while (option) {
        printf("  Option: %s = %s\n", 
               option->name ? option->name : "NULL",
               option->value ? option->value : "NULL");
        option = option->next;
    }
}

// Print all rules in the list
void print_rule_list(Rule* rule_list) {
    Rule* current = rule_list;
    int count = 0;
    
    while (current) {
        printf("=== Rule %d ===\n", ++count);
        print_rule(current);
        current = current->next;
    }
    
    if (count == 0) {
        printf("No rules found.\n");
    }
}
