/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_BUILD_FIREWALL_FIREWALL_PARSER_TAB_H_INCLUDED
# define YY_YY_BUILD_FIREWALL_FIREWALL_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 1 "./firewall_parser.y"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include "firewall_parser.h"

#line 59 "../build/firewall/firewall_parser.tab.h"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    TIMESTAMP = 258,               /* TIMESTAMP  */
    IP_ADDRESS = 259,              /* IP_ADDRESS  */
    HOSTNAME = 260,                /* HOSTNAME  */
    NUMBER = 261,                  /* NUMBER  */
    UFW_RESET = 262,               /* UFW_RESET  */
    UFW_DISABLE = 263,             /* UFW_DISABLE  */
    UFW_ENABLE = 264,              /* UFW_ENABLE  */
    SUDO_KEYWORD = 265,            /* SUDO_KEYWORD  */
    IPTABLES_FLUSH = 266,          /* IPTABLES_FLUSH  */
    IPTABLES_DELETE = 267,         /* IPTABLES_DELETE  */
    IPTABLES_RULE_CHANGE = 268,    /* IPTABLES_RULE_CHANGE  */
    FIREWALL_RELOAD = 269,         /* FIREWALL_RELOAD  */
    FIREWALL_STOP = 270,           /* FIREWALL_STOP  */
    CHMOD_DANGEROUS = 271,         /* CHMOD_DANGEROUS  */
    SU_ROOT = 272,                 /* SU_ROOT  */
    COLON = 273,                   /* COLON  */
    SEMICOLON = 274,               /* SEMICOLON  */
    AT = 275,                      /* AT  */
    SLASH = 276,                   /* SLASH  */
    DASH = 277,                    /* DASH  */
    EQUALS = 278,                  /* EQUALS  */
    NEWLINE = 279                  /* NEWLINE  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 35 "./firewall_parser.y"

    int number;
    char* string;
    FirewallEvent* event;

#line 106 "../build/firewall/firewall_parser.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_BUILD_FIREWALL_FIREWALL_PARSER_TAB_H_INCLUDED  */
