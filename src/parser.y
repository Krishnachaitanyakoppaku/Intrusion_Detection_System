%code requires {
#define _GNU_SOURCE
#include "../include/ast.h"
}

%{
#include "../include/ast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Forward declaration for rule_list
extern Rule* rule_list;

// Validation functions
static int validate_ip_address(const char* ip) {
    if (!ip || strcmp(ip, "any") == 0) return 1;
    
    int octets[4];
    int count = sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    if (count != 4) return 0;
    
    for (int i = 0; i < 4; i++) {
        if (octets[i] < 0 || octets[i] > 255) return 0;
    }
    return 1;
}

static int validate_port(const char* port_str) {
    if (!port_str || strcmp(port_str, "any") == 0) return 1;
    
    int port = atoi(port_str);
    if (port < 0 || port > 65535) return 0;
    return 1;
}

static int validate_protocol_action(const char* protocol, const char* action) {
    // ICMP doesn't use ports, but we'll allow it for flexibility
    if (!protocol || !action) return 0;
    return 1;
}

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
        // Validate IP addresses
        if (!validate_ip_address($3)) {
            fprintf(stderr, "ERROR: Invalid source IP address '%s' at line %d\n", $3, yylineno);
            yyerror("Invalid source IP address format");
            $$ = NULL;
            YYERROR;
        }
        if (!validate_ip_address($6)) {
            fprintf(stderr, "ERROR: Invalid destination IP address '%s' at line %d\n", $6, yylineno);
            yyerror("Invalid destination IP address format");
            $$ = NULL;
            YYERROR;
        }
        
        // Validate ports
        if (!validate_port($4)) {
            fprintf(stderr, "ERROR: Invalid source port '%s' at line %d (must be 0-65535)\n", $4, yylineno);
            yyerror("Invalid source port range");
            $$ = NULL;
            YYERROR;
        }
        if (!validate_port($7)) {
            fprintf(stderr, "ERROR: Invalid destination port '%s' at line %d (must be 0-65535)\n", $7, yylineno);
            yyerror("Invalid destination port range");
            $$ = NULL;
            YYERROR;
        }
        
        // Validate protocol-action combination
        if (!validate_protocol_action($2, $1)) {
            fprintf(stderr, "ERROR: Invalid protocol-action combination at line %d\n", yylineno);
            yyerror("Invalid protocol-action combination");
            $$ = NULL;
            YYERROR;
        }
        
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
        if (!$3 || strlen($3) == 0) {
            fprintf(stderr, "ERROR: Empty msg value at line %d\n", yylineno);
            yyerror("Empty msg option value");
            $$ = NULL;
            YYERROR;
        }
        $$ = create_rule_option("msg", $3);
    }
    | CONTENT COLON STRING
    {
        if (!$3 || strlen($3) == 0) {
            fprintf(stderr, "ERROR: Empty content value at line %d\n", yylineno);
            yyerror("Empty content option value");
            $$ = NULL;
            YYERROR;
        }
        $$ = create_rule_option("content", $3);
    }
    | SID COLON NUMBER
    {
        if ($3 < 0) {
            fprintf(stderr, "ERROR: Invalid SID value %d at line %d (must be >= 0)\n", $3, yylineno);
            yyerror("Invalid SID value");
            $$ = NULL;
            YYERROR;
        }
        char* sid_str = malloc(16);
        sprintf(sid_str, "%d", $3);
        $$ = create_rule_option("sid", sid_str);
        free(sid_str);
    }
    | REV COLON NUMBER
    {
        if ($3 < 0) {
            fprintf(stderr, "ERROR: Invalid rev value %d at line %d (must be >= 0)\n", $3, yylineno);
            yyerror("Invalid rev value");
            $$ = NULL;
            YYERROR;
        }
        char* rev_str = malloc(16);
        sprintf(rev_str, "%d", $3);
        $$ = create_rule_option("rev", rev_str);
        free(rev_str);
    }
    | CLASSTYPE COLON STRING
    {
        if (!$3 || strlen($3) == 0) {
            fprintf(stderr, "ERROR: Empty classtype value at line %d\n", yylineno);
            yyerror("Empty classtype option value");
            $$ = NULL;
            YYERROR;
        }
        $$ = create_rule_option("classtype", $3);
    }
    | PRIORITY COLON NUMBER
    {
        if ($3 < 0 || $3 > 10) {
            fprintf(stderr, "ERROR: Invalid priority value %d at line %d (must be 0-10)\n", $3, yylineno);
            yyerror("Invalid priority value");
            $$ = NULL;
            YYERROR;
        }
        char* priority_str = malloc(16);
        sprintf(priority_str, "%d", $3);
        $$ = create_rule_option("priority", priority_str);
        free(priority_str);
    }
    | REFERENCE COLON STRING
    {
        if (!$3 || strlen($3) == 0) {
            fprintf(stderr, "ERROR: Empty reference value at line %d\n", yylineno);
            yyerror("Empty reference option value");
            $$ = NULL;
            YYERROR;
        }
        $$ = create_rule_option("reference", $3);
    }
    ;

%%

// Global rule list
Rule* rule_list = NULL;

// Error handling function with enhanced error messages
void yyerror(const char* msg) {
    fprintf(stderr, "ERROR: Parse error at line %d: %s\n", yylineno, msg);
    if (yytext && strlen(yytext) > 0) {
        fprintf(stderr, "       Unexpected token near: '%s'\n", yytext);
    }
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
