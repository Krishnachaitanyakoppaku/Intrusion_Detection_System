%code requires {
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "firewall_parser.h"
}

%{
#include "firewall_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// External variables
extern int yylineno;
extern char* yytext;
extern FILE* yyin;

// Function declarations
int yylex(void);
void yyerror(const char* msg);

// Global list of detected events
FirewallEvent* event_list = NULL;
FirewallEvent* last_event = NULL;

%}

%union {
    int number;
    char* string;
    FirewallEvent* event;
}

%token <string> TIMESTAMP IP_ADDRESS HOSTNAME QUOTED_STRING
%token <number> NUMBER
%token UFW_RESET UFW_DISABLE UFW_ENABLE UFW_ALLOW UFW_DENY UFW_REJECT UFW_RELOAD
%token IPTABLES_FLUSH IPTABLES_DELETE_CHAIN IPTABLES_APPEND IPTABLES_DELETE IPTABLES_INSERT
%token FIREWALL_STOP FIREWALL_RELOAD CHMOD_DANGEROUS PRIVILEGE_ESCALATION
%token SUDO_KEYWORD ROOT_KEYWORD
%token COLON SEMICOLON AT SLASH DASH EQUALS NEWLINE

%type <event> log_entry firewall_command
%type <string> timestamp ip_address hostname command_text

%%

log_file:
    /* empty */
    | log_file log_entry
    {
        if ($2) {
            if (event_list == NULL) {
                event_list = $2;
                last_event = $2;
            } else {
                last_event->next = $2;
                last_event = $2;
            }
        }
    }
    ;

log_entry:
    timestamp hostname firewall_command {
        $$ = $3;
        if ($$) {
            if ($1) {
                $$->timestamp = $1;
            }
            if ($2) {
                $$->hostname = $2;
            }
        }
    }
    | timestamp firewall_command {
        $$ = $2;
        if ($$ && $1) {
            $$->timestamp = $1;
        }
    }
    | firewall_command {
        $$ = $1;
    }
    ;

firewall_command:
    UFW_RESET {
        $$ = create_firewall_event("ufw_reset", "critical", "UFW firewall rules were reset");
    }
    | UFW_DISABLE {
        $$ = create_firewall_event("ufw_disable", "critical", "UFW firewall was disabled");
    }
    | UFW_ENABLE {
        $$ = create_firewall_event("ufw_enable", "low", "UFW firewall was enabled");
    }
    | UFW_ALLOW {
        $$ = create_firewall_event("ufw_rule_add", "low", "UFW rule was added (allow)");
    }
    | UFW_DENY {
        $$ = create_firewall_event("ufw_rule_add", "low", "UFW rule was added (deny)");
    }
    | UFW_REJECT {
        $$ = create_firewall_event("ufw_rule_add", "low", "UFW rule was added (reject)");
    }
    | UFW_RELOAD {
        $$ = create_firewall_event("firewall_reload", "medium", "UFW firewall was reloaded");
    }
    | IPTABLES_FLUSH {
        $$ = create_firewall_event("iptables_flush", "critical", "iptables rules were flushed");
    }
    | IPTABLES_DELETE_CHAIN {
        $$ = create_firewall_event("iptables_delete", "critical", "iptables chain was deleted");
    }
    | IPTABLES_APPEND {
        $$ = create_firewall_event("iptables_rule_change", "medium", "iptables rule was appended");
    }
    | IPTABLES_DELETE {
        $$ = create_firewall_event("iptables_rule_change", "medium", "iptables rule was deleted");
    }
    | IPTABLES_INSERT {
        $$ = create_firewall_event("iptables_rule_change", "medium", "iptables rule was inserted");
    }
    | FIREWALL_STOP {
        $$ = create_firewall_event("firewall_stop", "critical", "Firewall service was stopped");
    }
    | FIREWALL_RELOAD {
        $$ = create_firewall_event("firewall_reload", "medium", "Firewall configuration was reloaded");
    }
    | CHMOD_DANGEROUS {
        $$ = create_firewall_event("chmod_dangerous", "high", "Dangerous file permissions change detected");
    }
    | PRIVILEGE_ESCALATION {
        $$ = create_firewall_event("privilege_escalation", "high", "Possible privilege escalation attempt");
    }
    | SUDO_KEYWORD firewall_command {
        $$ = $2;
        if ($$) {
            $$->severity = strcmp($$->severity, "low") == 0 ? strdup("medium") : $$->severity;
            if ($$->description) {
                char* new_desc = malloc(strlen($$->description) + 20);
                sprintf(new_desc, "Root/sudo: %s", $$->description);
                free($$->description);
                $$->description = new_desc;
            }
        }
    }
    ;

timestamp:
    TIMESTAMP { $$ = $1; }
    | NUMBER DASH NUMBER DASH NUMBER {
        // Format: YYYY-MM-DD
        $$ = malloc(32);
        sprintf($$, "%d-%02d-%02d", $1, $3, $5);
    }
    ;

hostname:
    HOSTNAME { $$ = $1; }
    | IP_ADDRESS { $$ = $1; }
    ;

ip_address:
    IP_ADDRESS { $$ = $1; }
    ;

command_text:
    QUOTED_STRING { $$ = $1; }
    | HOSTNAME { $$ = $1; }
    ;

%%

void yyerror(const char* msg) {
    fprintf(stderr, "Parse error at line %d: %s\n", yylineno, msg);
    fprintf(stderr, "Near: %s\n", yytext ? yytext : "(null)");
}

// Firewall event creation function
FirewallEvent* create_firewall_event(const char* event_type, const char* severity, const char* description) {
    FirewallEvent* event = (FirewallEvent*)malloc(sizeof(FirewallEvent));
    if (!event) return NULL;
    
    event->event_type = strdup(event_type);
    event->severity = strdup(severity);
    event->description = strdup(description);
    event->timestamp = NULL;
    event->source_ip = NULL;
    event->hostname = NULL;
    event->command = NULL;
    event->raw_line = NULL;
    event->next = NULL;
    
    return event;
}

// Main parsing function
FirewallEvent* parse_firewall_log(const char* log_line) {
    // Reset event list
    event_list = NULL;
    last_event = NULL;
    
    // Create temporary file with log line
    FILE* tmp_file = tmpfile();
    if (!tmp_file) {
        fprintf(stderr, "Error: Cannot create temporary file\n");
        return NULL;
    }
    
    fprintf(tmp_file, "%s\n", log_line);
    rewind(tmp_file);
    
    // Set input file
    yyin = tmp_file;
    yylineno = 1;
    
    // Parse
    int result = yyparse();
    
    // Close temp file (it will be deleted automatically)
    fclose(tmp_file);
    
    if (result == 0) {
        return event_list;
    }
    
    return NULL;
}

// Free firewall event list
void free_firewall_events(FirewallEvent* events) {
    FirewallEvent* current = events;
    while (current) {
        FirewallEvent* next = current->next;
        if (current->event_type) free(current->event_type);
        if (current->severity) free(current->severity);
        if (current->description) free(current->description);
        if (current->timestamp) free(current->timestamp);
        if (current->source_ip) free(current->source_ip);
        if (current->hostname) free(current->hostname);
        if (current->command) free(current->command);
        if (current->raw_line) free(current->raw_line);
        free(current);
        current = next;
    }
}

