%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/parser.h"
#include "../include/ast.h"

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

/* Keywords */
"alert"     { return ALERT; }
"log"       { return LOG; }
"pass"      { return PASS; }
"tcp"       { return TCP; }
"udp"       { return UDP; }
"icmp"      { return ICMP; }
"ip"        { return IP; }

/* Direction operators */
"->"        { return RIGHT_ARROW; }
"<>"        { return BIDIRECTIONAL; }

/* Rule options */
"msg"       { return MSG; }
"content"   { return CONTENT; }
"sid"       { return SID; }
"rev"       { return REV; }
"classtype" { return CLASSTYPE; }
"priority"  { return PRIORITY; }
"reference" { return REFERENCE; }

/* IP addresses and ports */
[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ { 
    yylval.string = strdup(yytext);
    return IP_ADDRESS; 
}

"any"       { 
    yylval.string = strdup("any");
    return IP_ADDRESS; 
}

[0-9]+      { 
    yylval.number = atoi(yytext);
    return NUMBER; 
}

"any"       { 
    yylval.string = strdup("any");
    return PORT; 
}

/* Strings in quotes */
\"([^\"\\]|\\.)*\" { 
    // Remove quotes and store the string
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return STRING; 
}

/* Single quoted strings */
\'([^\'\\]|\\.)*\' { 
    // Remove quotes and store the string
    int len = strlen(yytext);
    yylval.string = malloc(len - 1);
    strncpy(yylval.string, yytext + 1, len - 2);
    yylval.string[len - 2] = '\0';
    return STRING; 
}

/* Operators and delimiters */
"("         { return LPAREN; }
")"         { return RPAREN; }
";"         { return SEMICOLON; }
":"         { return COLON; }
","         { return COMMA; }
"!"         { return NOT; }
"|"         { return OR; }
"&"         { return AND; }

/* Whitespace - ignore */
[ \t\r]+    { /* ignore whitespace */ }

/* Newlines - count them */
\n          { yylineno++; }

/* Comments - ignore */
"#".*       { /* ignore comments */ }

/* Error handling */
.           { 
    fprintf(stderr, "Lexical error: unexpected character '%c' at line %d\n", 
            yytext[0], yylineno);
    return yytext[0]; 
}

%%

// Function to handle lexical errors
void yyerror(const char* msg) {
    fprintf(stderr, "Lexical error at line %d: %s\n", yylineno, msg);
}


