%{
/*
 * Firewall Log Lexer (Lex/Flex)
 * Focused on detecting "sudo ufw reset" and extracting IP addresses
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "firewall_parser.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

extern int yylineno;
extern char* yytext;
extern FILE* yyin;

void yyerror(const char* msg);
int yylex(void);
%}

%option yylineno
%option noyywrap
%option case-insensitive

%%

\[[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][ \t]+[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\] {
    yylval.string = strdup(yytext);
    return TIMESTAMP;
}

[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][ \t]+[0-9][0-9]:[0-9][0-9]:[0-9][0-9] {
    yylval.string = strdup(yytext);
    return TIMESTAMP;
}

[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ {
    yylval.string = strdup(yytext);
    return IP_ADDRESS;
}

sudo[ \t]+ufw[ \t]+reset {
    return UFW_RESET;
}

ufw[ \t]+reset {
    return UFW_RESET;
}

iptables[ \t] {
    return IPTABLES;
}

chmod[ \t]+777 {
    return CHMOD_777;
}

[a-zA-Z][a-zA-Z0-9._-]* {
    yylval.string = strdup(yytext);
    return HOSTNAME;
}


[ \t]+ {
    /* ignore whitespace */
}

\n {
    yylineno++;
    return NEWLINE;
}

. {
    /* ignore other characters */
}

%%

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
