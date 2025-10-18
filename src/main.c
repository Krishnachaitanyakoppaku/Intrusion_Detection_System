#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "../include/ast.h"
#include "../include/engine.h"

// External parser function
extern int parse_rules(const char* filename);
extern Rule* rule_list;

// Function declarations
void print_usage(const char* program_name);
void print_version(void);
int parse_arguments(int argc, char* argv[], char** rules_file, char** interface, 
                   char** log_file, int* promiscuous, int* timeout);

int main(int argc, char* argv[]) {
    char* rules_file = "rules/local.rules";
    char* interface = "eth0";
    char* log_file = "logs/alerts.log";
    int promiscuous = 1;
    int timeout = 1000;
    
    printf("IDS DSL Engine v1.0\n");
    printf("==================\n\n");
    
    // Parse command line arguments
    if (parse_arguments(argc, argv, &rules_file, &interface, &log_file, 
                        &promiscuous, &timeout) != 0) {
        return 1;
    }
    
    // Check if rules file exists
    FILE* file = fopen(rules_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open rules file '%s'\n", rules_file);
        return 1;
    }
    fclose(file);
    
    printf("Configuration:\n");
    printf("  Rules file: %s\n", rules_file);
    printf("  Interface: %s\n", interface);
    printf("  Log file: %s\n", log_file);
    printf("  Promiscuous mode: %s\n", promiscuous ? "enabled" : "disabled");
    printf("  Timeout: %d ms\n\n", timeout);
    
    // Parse rules file
    printf("Parsing rules file...\n");
    if (parse_rules(rules_file) != 0) {
        fprintf(stderr, "Error: Failed to parse rules file\n");
        return 1;
    }
    
    if (!rule_list) {
        fprintf(stderr, "Error: No rules found in file\n");
        return 1;
    }
    
    printf("Loaded %d rules\n", 0); // TODO: Count rules
    printf("Rules parsed successfully!\n\n");
    
    // Configure engine
    EngineConfig config;
    config.interface = interface;
    config.log_file = log_file;
    config.promiscuous = promiscuous;
    config.timeout = timeout;
    
    // Start the engine
    printf("Starting IDS engine...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    if (start_engine(rule_list, &config) != 0) {
        fprintf(stderr, "Error: Failed to start engine\n");
        free_rule_list(rule_list);
        return 1;
    }
    
    // Cleanup
    printf("Shutting down...\n");
    stop_engine();
    free_rule_list(rule_list);
    
    printf("IDS Engine stopped.\n");
    return 0;
}

// Parse command line arguments
int parse_arguments(int argc, char* argv[], char** rules_file, char** interface, 
                   char** log_file, int* promiscuous, int* timeout) {
    int opt;
    int option_index = 0;
    
    static struct option long_options[] = {
        {"rules", required_argument, 0, 'r'},
        {"interface", required_argument, 0, 'i'},
        {"log", required_argument, 0, 'l'},
        {"no-promiscuous", no_argument, 0, 'p'},
        {"timeout", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "r:i:l:pt:hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'r':
                *rules_file = strdup(optarg);
                break;
            case 'i':
                *interface = strdup(optarg);
                break;
            case 'l':
                *log_file = strdup(optarg);
                break;
            case 'p':
                *promiscuous = 0;
                break;
            case 't':
                *timeout = atoi(optarg);
                if (*timeout <= 0) {
                    fprintf(stderr, "Error: Timeout must be positive\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 'v':
                print_version();
                exit(0);
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    return 0;
}

// Print usage information
void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -r, --rules FILE        Rules file to load (default: rules/local.rules)\n");
    printf("  -i, --interface IFACE   Network interface to monitor (default: eth0)\n");
    printf("  -l, --log FILE          Log file for alerts (default: logs/alerts.log)\n");
    printf("  -p, --no-promiscuous    Disable promiscuous mode\n");
    printf("  -t, --timeout MS        Packet capture timeout in milliseconds (default: 1000)\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -v, --version           Show version information\n\n");
    printf("Examples:\n");
    printf("  %s                                    # Use defaults\n", program_name);
    printf("  %s -r myrules.rules -i wlan0         # Custom rules and interface\n", program_name);
    printf("  %s --no-promiscuous -t 500           # Disable promiscuous, 500ms timeout\n", program_name);
    printf("\nNote: This program requires root privileges to capture network packets.\n");
}

// Print version information
void print_version(void) {
    printf("IDS DSL Engine v1.0\n");
    printf("A Domain-Specific Query Language for Intrusion Detection Systems\n");
    printf("Built with Lex, Yacc, and libpcap\n");
}


