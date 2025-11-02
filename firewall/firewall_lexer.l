%{
/*
 * Firewall Log Lexer (Lex/Flex)
 * Tokenizes firewall log entries for parser
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "firewall_parser.h"

// Include generated parser header
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

// External variables
extern int yylineno;
extern char* yytext;
extern FILE* yyin;

// Function declarations
void yyerror(const char* msg);
int yylex(void);

%}

%option yylineno
%option noyywrap
%option case-insensitive

%%

/* Timestamp patterns */
\[[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}\] {
    yylval.string = strdup(yytext);
    return TIMESTAMP;
}

[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} {
    yylval.string = strdup(yytext);
    return TIMESTAMP;
}

[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2} {
    yylval.string = strdup(yytext);
    return TIMESTAMP;
}

/* IP Address patterns */
[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ {
    yylval.string = strdup(yytext);
    return IP_ADDRESS;
}

/* Firewall commands - UFW */
"ufw"[[:space:]]+"--force"[[:space:]]+"reset" {
    return UFW_RESET;
}

"ufw"[[:space:]]+"reset" {
    return UFW_RESET;
}

"ufw"[[:space:]]+"disable" {
    return UFW_DISABLE;
}

"ufw"[[:space:]]+"enable" {
    return UFW_ENABLE;
}

"ufw"[[:space:]]+"allow" {
    return UFW_ALLOW;
}

"ufw"[[:space:]]+"deny" {
    return UFW_DENY;
}

"ufw"[[:space:]]+"reject" {
    return UFW_REJECT;
}

"ufw"[[:space:]]+"reload" {
    return UFW_RELOAD;
}

/* Firewall commands - iptables */
"iptables"[[:space:]]+"-F" {
    return IPTABLES_FLUSH;
}

"iptables"[[:space:]]+"--flush" {
    return IPTABLES_FLUSH;
}

"iptables"[[:space:]]+"-X" {
    return IPTABLES_DELETE_CHAIN;
}

"iptables"[[:space:]]+"-A" {
    return IPTABLES_APPEND;
}

"iptables"[[:space:]]+"-D" {
    return IPTABLES_DELETE;
}

"iptables"[[:space:]]+"-I" {
    return IPTABLES_INSERT;
}

/* Firewall commands - systemctl */
"systemctl"[[:space:]]+"stop"[[:space:]]+"firewalld" {
    return FIREWALL_STOP;
}

"systemctl"[[:space:]]+"stop"[[:space:]]+"ufw" {
    return FIREWALL_STOP;
}

"systemctl"[[:space:]]+"reload"[[:space:]]+"firewalld" {
    return FIREWALL_RELOAD;
}

"firewall-cmd"[[:space:]]+"--reload" {
    return FIREWALL_RELOAD;
}

/* Dangerous chmod patterns */
"chmod"[[:space:]]+"777" {
    return CHMOD_DANGEROUS;
}

"chmod"[[:space:]]+"666" {
    return CHMOD_DANGEROUS;
}

"chmod"[[:space:]]+"000" {
    return CHMOD_DANGEROUS;
}

"chmod"[[:space:]]+"[0-7]{3}"[[:space:]]+"/etc/" {
    return CHMOD_DANGEROUS;
}

"chmod"[[:space:]]+"[0-7]{3}"[[:space:]]+"/usr/bin/" {
    return CHMOD_DANGEROUS;
}

/* Privilege escalation */
"su"[[:space:]]+"-" {
    return PRIVILEGE_ESCALATION;
}

"sudo"[[:space:]]+"su" {
    return PRIVILEGE_ESCALATION;
}

"sudo"[[:space:]]+"bash" {
    return PRIVILEGE_ESCALATION;
}

/* Root/sudo keywords */
"sudo" {
    return SUDO_KEYWORD;
}

"root" {
    return ROOT_KEYWORD;
}

/* Hostname patterns */
[a-zA-Z0-9_-]+ {
    // Check if it's not a command keyword
    if (strlen(yytext) > 0) {
        yylval.string = strdup(yytext);
        return HOSTNAME;
    }
    return UNKNOWN_TOKEN;
}

/* Whitespace */
[[:space:]]+ {
    /* Ignore whitespace */
}

/* Newline */
\n {
    yylineno++;
    return NEWLINE;
}

/* Punctuation and operators */
":" { return COLON; }
";" { return SEMICOLON; }
"@" { return AT; }
"/" { return SLASH; }
"-" { return DASH; }
"=" { return EQUALS; }

/* Quoted strings */
\"[^"]*\" {
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return QUOTED_STRING;
}

'[^']*' {
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return QUOTED_STRING;
}

/* Numbers */
[0-9]+ {
    yylval.number = atoi(yytext);
    return NUMBER;
}

/* Any other character */
. {
    // Return as-is for parser to handle context
    return yytext[0];
}

%%

int yywrap(void) {
    return 1;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

