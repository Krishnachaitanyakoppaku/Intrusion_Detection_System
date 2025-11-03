#ifndef RULES_PARSER_H
#define RULES_PARSER_H

#include "ast.h"

// Forward declaration
typedef struct Rule Rule;

// External rule list
extern Rule* rule_list;

// Function to parse rules file
int parse_rules(const char* filename);

#endif // RULES_PARSER_H

