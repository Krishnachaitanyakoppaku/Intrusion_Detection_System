%code requires {
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include "firewall_parser.h"
}

%{
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "firewall_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include <ctype.h>

extern int yylineno;
extern char* yytext;
extern FILE* yyin;

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

%token <string> TIMESTAMP IP_ADDRESS HOSTNAME
%token <number> NUMBER
%token UFW_RESET IPTABLES CHMOD_777
%token COLON SEMICOLON AT SLASH DASH EQUALS NEWLINE

%type <event> log_entry firewall_command
%type <string> timestamp

%%

log_file:
    /* empty */
    | log_file tokens_optional firewall_command tokens_optional
    {
        if ($3) {
            if (event_list == NULL) {
                event_list = $3;
                last_event = $3;
            } else {
                last_event->next = $3;
                last_event = $3;
            }
        }
    }
    | log_file tokens_optional
    {
        /* Ignore lines without firewall commands */
    }
    ;

tokens_optional:
    /* empty */
    | tokens_optional any_token
    {
        /* Accept any tokens */
    }
    ;

any_token:
    TIMESTAMP | IP_ADDRESS | HOSTNAME | NUMBER | COLON | SEMICOLON | AT | SLASH | DASH | EQUALS | NEWLINE
    ;

log_entry:
    firewall_command {
        $$ = $1;
    }
    | any_token firewall_command {
        $$ = $2;
    }
    | firewall_command any_token {
        $$ = $1;
    }
    | any_token firewall_command any_token {
        $$ = $2;
    }
    | any_token any_token firewall_command {
        $$ = $3;
    }
    | firewall_command any_token any_token {
        $$ = $1;
    }
    | any_token any_token firewall_command any_token {
        $$ = $3;
    }
    | timestamp firewall_command {
        $$ = $2;
        if ($$ && $1) {
            $$->timestamp = $1;
        }
    }
    | firewall_command timestamp {
        $$ = $1;
        if ($$ && $2) {
            $$->timestamp = $2;
        }
    }
    | firewall_command IP_ADDRESS {
        $$ = $1;
        if ($$ && $2) {
            $$->source_ip = $2;
        }
    }
    | IP_ADDRESS firewall_command {
        $$ = $2;
        if ($$ && $1) {
            $$->source_ip = $1;
        }
    }
    | any_token firewall_command IP_ADDRESS {
        $$ = $2;
        if ($$ && $3) {
            $$->source_ip = $3;
        }
    }
    | IP_ADDRESS any_token firewall_command {
        $$ = $3;
        if ($$ && $1) {
            $$->source_ip = $1;
        }
    }
    | HOSTNAME firewall_command {
        $$ = $2;
        if ($$ && $1) {
            $$->hostname = $1;
        }
    }
    | firewall_command HOSTNAME {
        $$ = $1;
        if ($$ && $2) {
            $$->hostname = $2;
        }
    }
    ;

firewall_command:
    UFW_RESET {
        $$ = create_firewall_event("ufw_reset", "critical", "UFW firewall rules were reset");
    }
    | IPTABLES {
        $$ = create_firewall_event("iptables", "critical", "IPTables command detected");
    }
    | CHMOD_777 {
        $$ = create_firewall_event("chmod_777", "critical", "Dangerous file permissions change detected (chmod 777)");
    }
    ;

timestamp:
    TIMESTAMP { $$ = $1; }
    ;

%%

void yyerror(const char* msg) {
    // Silently ignore parse errors - we only care about matching patterns
}

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

// Extract last IP address from log line using manual parsing
static char* extract_last_ip(const char* log_line) {
    if (!log_line || !log_line[0]) return NULL;
    
    size_t len = strlen(log_line);
    if (len == 0 || len > 4096) return NULL;
    
    // Find the last IP address by scanning backwards
    const char* last_ip_start = NULL;
    const char* last_ip_end = NULL;
    
    // Scan from the end to find the last IP-like pattern
    for (int i = len - 1; i >= 0; i--) {
        if (isdigit((unsigned char)log_line[i]) || log_line[i] == '.') {
            // Found potential IP character, check if it's part of an IP
            int j = i;
            int dots = 0;
            int valid = 1;
            
            // Check backwards to find start of IP
            while (j >= 0 && (isdigit((unsigned char)log_line[j]) || log_line[j] == '.')) {
                if (log_line[j] == '.') {
                    dots++;
                }
                j--;
            }
            
            // Check forwards to find end of IP
            int start = j + 1;
            int end = i + 1;
            dots = 0;
            for (int k = start; k < end && k < len; k++) {
                if (log_line[k] == '.') {
                    dots++;
                } else if (!isdigit((unsigned char)log_line[k])) {
                    valid = 0;
                    break;
                }
            }
            
            // If we found a valid IP (3 dots, only digits and dots)
            if (valid && dots == 3 && (end - start) >= 7 && (end - start) <= 15) {
                // Check if this is the last one (after start, no more IPs)
                if (!last_ip_start || start > (last_ip_start - log_line)) {
                    last_ip_start = log_line + start;
                    last_ip_end = log_line + end;
                    break;
                }
            }
            
            // Skip past this potential IP
            i = start - 1;
        }
    }
    
    if (last_ip_start && last_ip_end) {
        size_t ip_len = last_ip_end - last_ip_start;
        char* ip = (char*)malloc(ip_len + 1);
        if (ip) {
            strncpy(ip, last_ip_start, ip_len);
            ip[ip_len] = '\0';
            return ip;
        }
    }
    
    return NULL;
}

FirewallEvent* parse_firewall_log(const char* log_line) {
    // Reset event list
    event_list = NULL;
    last_event = NULL;
    
    if (!log_line || !log_line[0]) {
        return NULL;
    }
    
    // Create temporary file with log line
    FILE* tmp_file = tmpfile();
    if (!tmp_file) {
        return NULL;
    }
    
    fprintf(tmp_file, "%s\n", log_line);
    rewind(tmp_file);
    
    // Set input file
    yyin = tmp_file;
    yylineno = 1;
    
    // Parse
    int result = yyparse();
    
    // Close temp file
    fclose(tmp_file);
    
    if (result == 0 && event_list) {
        // Enrich events with raw_line, timestamp, and extract last IP
        FirewallEvent* cur = event_list;
        while (cur) {
            if (!cur->raw_line && log_line) {
                cur->raw_line = strdup(log_line);
            }
            
            // Extract timestamp from log line if not already set
            if (!cur->timestamp && log_line) {
                // Look for timestamp pattern [YYYY-MM-DD HH:MM:SS]
                const char* ts_start = strchr(log_line, '[');
                if (ts_start) {
                    const char* ts_end = strchr(ts_start + 1, ']');
                    if (ts_end && ts_end > ts_start + 1) {
                        size_t ts_len = ts_end - ts_start - 1;
                        if (ts_len > 0 && ts_len < 256) {
                            cur->timestamp = malloc(ts_len + 1);
                            if (cur->timestamp) {
                                strncpy(cur->timestamp, ts_start + 1, ts_len);
                                cur->timestamp[ts_len] = '\0';
                            }
                        }
                    }
                }
                // If no bracket format, try to find YYYY-MM-DD HH:MM:SS pattern
                if (!cur->timestamp) {
                    // Pattern: YYYY-MM-DD HH:MM:SS
                    const char* pattern = log_line;
                    while (*pattern) {
                        if (isdigit((unsigned char)pattern[0]) && 
                            isdigit((unsigned char)pattern[1]) &&
                            isdigit((unsigned char)pattern[2]) &&
                            isdigit((unsigned char)pattern[3]) &&
                            pattern[4] == '-' &&
                            isdigit((unsigned char)pattern[5]) &&
                            isdigit((unsigned char)pattern[6]) &&
                            pattern[7] == '-' &&
                            isdigit((unsigned char)pattern[8]) &&
                            isdigit((unsigned char)pattern[9])) {
                            // Found date pattern, check for time
                            const char* time_start = pattern + 10;
                            while (*time_start == ' ' || *time_start == '\t') time_start++;
                            if (isdigit((unsigned char)time_start[0]) &&
                                isdigit((unsigned char)time_start[1]) &&
                                time_start[2] == ':' &&
                                isdigit((unsigned char)time_start[3]) &&
                                isdigit((unsigned char)time_start[4]) &&
                                time_start[5] == ':' &&
                                isdigit((unsigned char)time_start[6]) &&
                                isdigit((unsigned char)time_start[7])) {
                                // Found full timestamp, extract it
                                const char* ts_end = time_start + 8;
                                while (*ts_end && *ts_end != ' ' && *ts_end != '\t' && *ts_end != '\n' && *ts_end != '\r') ts_end++;
                                size_t ts_len = ts_end - pattern;
                                if (ts_len > 0 && ts_len < 256) {
                                    cur->timestamp = malloc(ts_len + 1);
                                    if (cur->timestamp) {
                                        strncpy(cur->timestamp, pattern, ts_len);
                                        cur->timestamp[ts_len] = '\0';
                                    }
                                }
                                break;
                            }
                        }
                        pattern++;
                    }
                }
            }
            
            // Extract last IP address from log line if not already set
            if (!cur->source_ip && log_line) {
                cur->source_ip = extract_last_ip(log_line);
            }
            
            // Extract command
            if (!cur->command && log_line) {
                const char* p = strcasestr(log_line, "COMMAND=");
                if (p) {
                    p += 8; // Skip "COMMAND="
                    while (*p == ' ') p++;
                    const char* end = p;
                    while (*end && *end != '\n' && *end != ';' && *end != '\r') end++;
                    size_t len = end - p;
                    if (len > 0) {
                        cur->command = malloc(len + 1);
                        strncpy(cur->command, p, len);
                        cur->command[len] = '\0';
                    }
                } else {
                    p = strcasestr(log_line, "executed:");
                    if (p) {
                        p += 9; // Skip "executed:"
                        while (*p == ' ') p++;
                        const char* end = p;
                        while (*end && *end != '\n' && *end != '\r') end++;
                        size_t len = end - p;
                        if (len > 0) {
                            cur->command = malloc(len + 1);
                            strncpy(cur->command, p, len);
                            cur->command[len] = '\0';
                        }
                    }
                }
            }
            
            cur = cur->next;
        }
        return event_list;
    }
    
    return NULL;
}

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



