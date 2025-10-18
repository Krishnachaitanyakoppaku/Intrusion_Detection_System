#ifndef NLP_PARSER_H
#define NLP_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function declarations for AI-powered natural language processing
char* convert_natural_language_to_dsl(const char* natural_language, const char* api_key);
void interactive_nlp_rule_creator(const char* api_key);
int validate_dsl_rule(const char* dsl_rule);
int save_rule_to_file(const char* dsl_rule, const char* filename);

// Example natural language inputs and their DSL conversions
typedef struct {
    char* natural_language;
    char* dsl_rule;
    char* description;
} RuleExample;

// Pre-defined rule examples
extern RuleExample rule_examples[];
extern int num_rule_examples;

// Utility functions
char* clean_whitespace(const char* input);
int is_valid_ip_address(const char* ip);
int is_valid_port(const char* port);
char* extract_keywords(const char* natural_language);

#endif // NLP_PARSER_H
