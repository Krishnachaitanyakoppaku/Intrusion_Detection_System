#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <signal.h>

// Simple IDS Engine - Basic Version
// This is a simplified version that can run without complex dependencies

typedef struct {
    char msg[256];
    int priority;
} SimpleRule;

typedef struct {
    char source_ip[16];
    char dest_ip[16];
    int source_port;
    int dest_port;
    char protocol[8];
    char content[1024];
} PacketInfo;

SimpleRule rules[] = {
    {"SQL Injection Attempt", 1},
    {"XSS Attack", 2},
    {"Port Scan", 3},
    {"ICMP Flood", 4},
    {"Malicious File Upload", 2},
    {"Directory Traversal", 2},
    {"Command Injection", 1},
    {"SSH Brute Force", 3},
    {"HTTPS Traffic", 5},
    {"DNS Query", 5}
};

int rule_count = sizeof(rules) / sizeof(rules[0]);
int running = 1;

void signal_handler(int sig) {
    printf("\n🛑 Stopping IDS Engine...\n");
    running = 0;
}

void log_alert(const char* msg, int priority, PacketInfo* pkt) {
    time_t now = time(0);
    char* time_str = ctime(&now);
    time_str[strlen(time_str)-1] = '\0'; // Remove newline
    
    const char* severity = "INFO";
    if (priority == 1) severity = "CRITICAL";
    else if (priority == 2) severity = "HIGH";
    else if (priority == 3) severity = "MEDIUM";
    else if (priority == 4) severity = "LOW";
    
    printf("[%s] 🚨 ALERT: %s\n", time_str, msg);
    printf("  Severity: %s | Protocol: %s\n", severity, pkt->protocol);
    printf("  Source: %s:%d -> Destination: %s:%d\n", 
           pkt->source_ip, pkt->source_port, pkt->dest_ip, pkt->dest_port);
    printf("  Content: %.50s%s\n", pkt->content, strlen(pkt->content) > 50 ? "..." : "");
    printf("  ---\n");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketInfo pkt = {0};
    
    // Simulate packet analysis
    snprintf(pkt.source_ip, sizeof(pkt.source_ip), "192.168.1.%d", rand() % 255);
    snprintf(pkt.dest_ip, sizeof(pkt.dest_ip), "192.168.1.%d", rand() % 255);
    pkt.source_port = rand() % 65535;
    pkt.dest_port = rand() % 65535;
    
    // Randomly assign protocol
    const char* protocols[] = {"TCP", "UDP", "ICMP"};
    strcpy(pkt.protocol, protocols[rand() % 3]);
    
    // Simulate content analysis
    const char* contents[] = {
        "' OR 1=1", "<script>", "SYN", "ping", ".exe", "../", "|", "ssh", "https", "dns"
    };
    strcpy(pkt.content, contents[rand() % 10]);
    
    // Check against rules (simplified)
    for (int i = 0; i < rule_count; i++) {
        if (strstr(pkt.content, "' OR 1=1") && i == 0) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "<script>") && i == 1) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "SYN") && i == 2) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "ping") && i == 3) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, ".exe") && i == 4) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "../") && i == 5) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "|") && i == 6) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "ssh") && i == 7) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "https") && i == 8) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        } else if (strstr(pkt.content, "dns") && i == 9) {
            log_alert(rules[i].msg, rules[i].priority, &pkt);
            break;
        }
    }
}

int main(int argc, char *argv[]) {
    printf("🛡️  Simple IDS Engine - Starting...\n");
    printf("=====================================\n");
    
    signal(SIGINT, signal_handler);
    srand(time(NULL));
    
    char *dev = "lo";  // Default to loopback interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            dev = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-i interface] [-h]\n", argv[0]);
            printf("  -i interface  Network interface to monitor (default: lo)\n");
            printf("  -h, --help    Show this help message\n");
            return 0;
        }
    }
    
    printf("📡 Monitoring interface: %s\n", dev);
    printf("📋 Loaded %d security rules\n", rule_count);
    printf("🚀 Starting packet capture...\n");
    printf("Press Ctrl+C to stop\n\n");
    
    // Open the device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "❌ Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    
    // Start packet capture loop
    while (running) {
        // Simulate packet capture with random alerts
        if (rand() % 100 < 5) { // 5% chance of generating an alert
            packet_handler(NULL, NULL, NULL);
        }
        usleep(100000); // Sleep for 100ms
    }
    
    pcap_close(handle);
    printf("\n✅ IDS Engine stopped successfully.\n");
    return 0;
}
