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

#ifndef YY_PKT_SRC_PACKET_PARSER_TAB_H_INCLUDED
# define YY_PKT_SRC_PACKET_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef PKTDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define PKTDEBUG 1
#  else
#   define PKTDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define PKTDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined PKTDEBUG */
#if PKTDEBUG
extern int pktdebug;
#endif
/* "%code requires" blocks.  */
#line 1 "src/packet_parser.y"

#define _GNU_SOURCE
#include "../include/packet_parser.h"

#line 62 "src/packet_parser.tab.h"

/* Token kinds.  */
#ifndef PKTTOKENTYPE
# define PKTTOKENTYPE
  enum pkttokentype
  {
    PKTEMPTY = -2,
    PKTEOF = 0,                    /* "end of file"  */
    PKTerror = 256,                /* error  */
    PKTUNDEF = 257,                /* "invalid token"  */
    DATE = 258,                    /* DATE  */
    TIME = 259,                    /* TIME  */
    IP_ADDRESS = 260,              /* IP_ADDRESS  */
    PROTOCOL = 261,                /* PROTOCOL  */
    WORD = 262,                    /* WORD  */
    NUMBER = 263,                  /* NUMBER  */
    ARROW = 264,                   /* ARROW  */
    PIPE = 265,                    /* PIPE  */
    COLON = 266,                   /* COLON  */
    SIZE_KEYWORD = 267,            /* SIZE_KEYWORD  */
    UNKNOWN_PACKET = 268,          /* UNKNOWN_PACKET  */
    NEWLINE = 269                  /* NEWLINE  */
  };
  typedef enum pkttokentype pkttoken_kind_t;
#endif

/* Value type.  */
#if ! defined PKTSTYPE && ! defined PKTSTYPE_IS_DECLARED
union PKTSTYPE
{
#line 34 "src/packet_parser.y"

    int number;
    char* string;

#line 98 "src/packet_parser.tab.h"

};
typedef union PKTSTYPE PKTSTYPE;
# define PKTSTYPE_IS_TRIVIAL 1
# define PKTSTYPE_IS_DECLARED 1
#endif


extern PKTSTYPE pktlval;


int pktparse (void);


#endif /* !YY_PKT_SRC_PACKET_PARSER_TAB_H_INCLUDED  */
