#ifndef RULE_MATCHER_H
#define RULE_MATCHER_H

#include "packet_parser.h"
#include "ast.h"

// Function declarations
int packet_matches_rule(ParsedPacket* packet, Rule* rule);
void write_alert(ParsedPacket* packet, Rule* rule);
void match_packet_against_rules(ParsedPacket* packet, Rule* rule_list);

#endif // RULE_MATCHER_H

