%{
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/ast.h"
#include "../include/parser.h"

// Provide a portable strdup replacement for strict C99 builds
static char* duplicate_string_rules(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}
#define strdup duplicate_string_rules

// External variables for parser communication
extern Rule* rule_list;
extern int yylineno;
extern char* yytext;

// Function to handle errors
void yyerror(const char* msg);
%}

%option yylineno
%option noyywrap

%%

"alert"     { return ALERT; }
"log"       { return LOG; }
"pass"      { return PASS; }
"tcp"       { return TCP; }
"udp"       { return UDP; }
"icmp"      { return ICMP; }
"ip"        { return IP; }

"->"        { return RIGHT_ARROW; }
"<>"        { return BIDIRECTIONAL; }

"msg"       { return MSG; }
"content"   { return CONTENT; }
"sid"       { return SID; }
"rev"       { return REV; }
"classtype" { return CLASSTYPE; }
"priority"  { return PRIORITY; }
"reference" { return REFERENCE; }

[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ { 
    yylval.string = strdup(yytext);
    return IP_ADDRESS; 
}

"any"       { 
    yylval.string = strdup("any");
    return ANY; 
}

[0-9]+      { 
    yylval.number = atoi(yytext);
    return NUMBER; 
}

\"[^\"]*\" { 
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return STRING; 
}

\'[^\']*\' { 
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return STRING; 
}

"("         { return LPAREN; }
")"         { return RPAREN; }
";"         { return SEMICOLON; }
":"         { return COLON; }
","         { return COMMA; }
"!"         { return NOT; }
"|"         { return OR; }
"&"         { return AND; }

[ \t\r]+    { }

\n          { yylineno++; }

"#"[^\n]*       { }

.           { 
    fprintf(stderr, "ERROR: Lexical error at line %d: unexpected character '%c' (ASCII: %d)\n", 
            yylineno, yytext[0], (int)yytext[0]);
    fprintf(stderr, "       Expected: valid rule token (alert, log, pass, tcp, udp, icmp, etc.)\n");
    return yytext[0]; 
}

%%
