%{
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/packet_parser.h"
// Include Bison-generated tokens and yylval
#include "packet_parser.tab.h"

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

// External variables for parser communication
extern int yylineno;
extern char* yytext;
extern ParsedPacket* parsed_packet;
%}

%option yylineno
%option noyywrap
%option prefix="pkt"

%%

[0-9]{4}-[0-9]{2}-[0-9]{2} {
    // Timestamp date part
    pktlval.string = strdup(pkttext);
    return DATE;
}

[0-9]{2}:[0-9]{2}:[0-9]{2} {
    // Timestamp time part
    pktlval.string = strdup(pkttext);
    return TIME;
}

[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ {
    // IP address
    pktlval.string = strdup(pkttext);
    return IP_ADDRESS;
}

[0-9]+ {
    // Port number or size number
    pktlval.number = atoi(pkttext);
    return NUMBER;
}

"->" {
    return ARROW;
}

"|" {
    return PIPE;
}

":" {
    return COLON;
}

"Size:" {
    return SIZE_KEYWORD;
}

"Unknown packet" {
    return UNKNOWN_PACKET;
}

"TCP" { pktlval.string = strdup("TCP"); return PROTOCOL; }
"UDP" { pktlval.string = strdup("UDP"); return PROTOCOL; }
"ICMP" { pktlval.string = strdup("ICMP"); return PROTOCOL; }
"IP" { pktlval.string = strdup("IP"); return PROTOCOL; }
"Unknown" { pktlval.string = strdup("Unknown"); return PROTOCOL; }

[A-Za-z][A-Za-z0-9]* { pktlval.string = strdup(pkttext); return WORD; }

[ \t]+ {
    // Whitespace - ignore
}

\n {
    pktlineno++;
    return NEWLINE;
}

. {
    // Any other character - report as error
    fprintf(stderr, "ERROR: Packet log lexical error at line %d: unexpected character '%c' (ASCII: %d)\n", 
            pktlineno, pkttext[0], (int)pkttext[0]);
    fprintf(stderr, "       Expected: valid log format tokens\n");
    return pkttext[0];
}

%%

