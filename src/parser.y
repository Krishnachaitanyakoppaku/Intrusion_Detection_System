%code requires {
#define _GNU_SOURCE
#include "../include/ast.h"
}

%{
#include "../include/ast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration for rule_list
extern Rule* rule_list;

// External variables
extern int yylineno;
extern char* yytext;
extern FILE* yyin;

// Function declarations
int yylex(void);
void yyerror(const char* msg);

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
%}

%union {
    int number;
    char* string;
    Rule* rule;
    RuleOption* option;
}

%token <string> IP_ADDRESS PORT STRING ANY
%token <number> NUMBER
%token ALERT LOG PASS TCP UDP ICMP IP
%token RIGHT_ARROW BIDIRECTIONAL
%token MSG CONTENT SID REV CLASSTYPE PRIORITY REFERENCE
%token LPAREN RPAREN SEMICOLON COLON COMMA NOT OR AND

%type <rule> rule
%type <option> rule_option rule_options
%type <string> action protocol direction ip_address port

%%

rules:
    /* empty */
    | rules rule
    {
        if ($2) {
            add_rule_to_list(&rule_list, $2);
        }
    }
    | rules rule SEMICOLON
    {
        if ($2) {
            add_rule_to_list(&rule_list, $2);
        }
    }
    ;

rule:
    action protocol ip_address port direction ip_address port LPAREN rule_options RPAREN
    {
        $$ = create_rule($1, $2, $3, $4, $5, $6, $7);
        if ($$ && $9) {
            // Add options to the rule
            RuleOption* current = $9;
            while (current) {
                add_option_to_rule($$, current->name, current->value);
                current = current->next;
            }
        }
    }
    ;

action:
    ALERT { $$ = strdup("alert"); }
    | LOG { $$ = strdup("log"); }
    | PASS { $$ = strdup("pass"); }
    ;

protocol:
    TCP { $$ = strdup("tcp"); }
    | UDP { $$ = strdup("udp"); }
    | ICMP { $$ = strdup("icmp"); }
    | IP { $$ = strdup("ip"); }
    ;

direction:
    RIGHT_ARROW { $$ = strdup("->"); }
    | BIDIRECTIONAL { $$ = strdup("<>"); }
    ;

ip_address:
    IP_ADDRESS { $$ = $1; }
    | ANY { $$ = $1; }
    | STRING { $$ = $1; }
    ;

port:
    PORT { $$ = $1; }
    | ANY { $$ = $1; }
    | IP_ADDRESS { $$ = $1; }
    | NUMBER { 
        $$ = malloc(16);
        sprintf($$, "%d", $1);
    }
    | STRING { $$ = $1; }  /* allow 'any' and quoted ports */
    ;

rule_options:
    /* empty */ { $$ = NULL; }
    | rule_options rule_option
    {
        if ($2) {
            $2->next = $1;
            $$ = $2;
        } else {
            $$ = $1;
        }
    }
    | rule_options rule_option SEMICOLON
    {
        if ($2) {
            $2->next = $1;
            $$ = $2;
        } else {
            $$ = $1;
        }
    }
    ;

rule_option:
    MSG COLON STRING
    {
        $$ = create_rule_option("msg", $3);
    }
    | CONTENT COLON STRING
    {
        $$ = create_rule_option("content", $3);
    }
    | SID COLON NUMBER
    {
        char* sid_str = malloc(16);
        sprintf(sid_str, "%d", $3);
        $$ = create_rule_option("sid", sid_str);
        free(sid_str);
    }
    | REV COLON NUMBER
    {
        char* rev_str = malloc(16);
        sprintf(rev_str, "%d", $3);
        $$ = create_rule_option("rev", rev_str);
        free(rev_str);
    }
    | CLASSTYPE COLON STRING
    {
        $$ = create_rule_option("classtype", $3);
    }
    | PRIORITY COLON NUMBER
    {
        char* priority_str = malloc(16);
        sprintf(priority_str, "%d", $3);
        $$ = create_rule_option("priority", priority_str);
        free(priority_str);
    }
    | REFERENCE COLON STRING
    {
        $$ = create_rule_option("reference", $3);
    }
    ;

%%

// Global rule list
Rule* rule_list = NULL;

// Error handling function
void yyerror(const char* msg) {
    fprintf(stderr, "Parse error at line %d: %s\n", yylineno, msg);
    fprintf(stderr, "Near: %s\n", yytext);
}

// Main parsing function
int parse_rules(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 1;
    }
    
    // Set input file for lexer
    yyin = file;
    
    // Parse the file
    int result = yyparse();
    
    fclose(file);
    return result;
}
