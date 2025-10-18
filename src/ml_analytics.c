#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "../include/ast.h"

// Machine Learning Analytics for IDS
typedef struct {
    int total_packets;
    int total_alerts;
    int sql_injection_count;
    int xss_count;
    int port_scan_count;
    int brute_force_count;
    double threat_score;
    time_t last_analysis;
} ThreatAnalytics;

// Anomaly detection
typedef struct {
    double baseline_avg;
    double current_avg;
    double deviation;
    int anomaly_detected;
} AnomalyDetection;

// Function to calculate threat score
double calculate_threat_score(ThreatAnalytics* analytics) {
    if (analytics->total_packets == 0) return 0.0;
    
    double score = 0.0;
    
    // Weight different threat types
    score += analytics->sql_injection_count * 10.0;
    score += analytics->xss_count * 8.0;
    score += analytics->port_scan_count * 6.0;
    score += analytics->brute_force_count * 7.0;
    
    // Normalize by total packets
    score = (score / analytics->total_packets) * 100.0;
    
    return fmin(score, 100.0);
}

// Detect anomalies in network traffic
AnomalyDetection* detect_anomalies(ThreatAnalytics* current, ThreatAnalytics* baseline) {
    AnomalyDetection* detection = malloc(sizeof(AnomalyDetection));
    if (!detection) return NULL;
    
    detection->baseline_avg = baseline->threat_score;
    detection->current_avg = current->threat_score;
    detection->deviation = fabs(current->threat_score - baseline->threat_score);
    detection->anomaly_detected = (detection->deviation > 20.0) ? 1 : 0;
    
    return detection;
}

// Generate security report
void generate_security_report(ThreatAnalytics* analytics) {
    printf("\n=== IDS Security Report ===\n");
    printf("Total Packets Analyzed: %d\n", analytics->total_packets);
    printf("Total Alerts Generated: %d\n", analytics->total_alerts);
    printf("Threat Score: %.2f/100\n", analytics->threat_score);
    printf("\nThreat Breakdown:\n");
    printf("  SQL Injection Attempts: %d\n", analytics->sql_injection_count);
    printf("  XSS Attacks: %d\n", analytics->xss_count);
    printf("  Port Scans: %d\n", analytics->port_scan_count);
    printf("  Brute Force Attacks: %d\n", analytics->brute_force_count);
    printf("\nRisk Assessment: ");
    
    if (analytics->threat_score < 20) {
        printf("LOW RISK\n");
    } else if (analytics->threat_score < 50) {
        printf("MEDIUM RISK\n");
    } else if (analytics->threat_score < 80) {
        printf("HIGH RISK\n");
    } else {
        printf("CRITICAL RISK\n");
    }
}

// Predictive threat analysis
int predict_threat_level(ThreatAnalytics* historical, int time_window_minutes) {
    // Simple prediction based on trend analysis
    double trend = 0.0;
    
    if (historical->total_packets > 0) {
        trend = (double)historical->total_alerts / historical->total_packets;
    }
    
    // Predict based on trend
    if (trend > 0.1) {
        return 3; // High threat
    } else if (trend > 0.05) {
        return 2; // Medium threat
    } else {
        return 1; // Low threat
    }
}
