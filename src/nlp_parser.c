#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "../include/ast.h"

// AI API Configuration
#define OPENAI_API_URL "https://api.openai.com/v1/chat/completions"
#define OPENAI_MODEL "gpt-3.5-turbo"

// Structure for AI API response
typedef struct {
    char* content;
    int success;
    char* error_message;
} AIResponse;

// Callback function for curl to write response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    AIResponse *response = (AIResponse *)userp;
    
    char *ptr = realloc(response->content, response->content ? strlen(response->content) + realsize + 1 : realsize + 1);
    if (!ptr) {
        return 0;
    }
    
    if (!response->content) {
        ptr[0] = '\0';
    }
    
    response->content = ptr;
    strncat(response->content, (char *)contents, realsize);
    return realsize;
}

// Function to make HTTP request to AI API
AIResponse* call_ai_api(const char* prompt, const char* api_key) {
    CURL *curl;
    CURLcode res;
    AIResponse *response = malloc(sizeof(AIResponse));
    
    if (!response) {
        return NULL;
    }
    
    response->success = 0;
    response->content = NULL;
    response->error_message = NULL;
    
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        char *json_payload = NULL;
        
        // Prepare JSON payload
        json_object *json_obj = json_object_new_object();
        json_object *messages = json_object_new_array();
        json_object *message = json_object_new_object();
        
        json_object_object_add(message, "role", json_object_new_string("user"));
        json_object_object_add(message, "content", json_object_new_string(prompt));
        json_object_array_add(messages, message);
        
        json_object_object_add(json_obj, "model", json_object_new_string(OPENAI_MODEL));
        json_object_object_add(json_obj, "messages", messages);
        json_object_object_add(json_obj, "max_tokens", json_object_new_int(500));
        json_object_object_add(json_obj, "temperature", json_object_new_double(0.1));
        
        json_payload = (char*)json_object_to_json_string(json_obj);
        
        // Set headers
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, auth_header);
        
        // Set curl options
        curl_easy_setopt(curl, CURLOPT_URL, OPENAI_API_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            response->error_message = strdup(curl_easy_strerror(res));
        } else {
            response->success = 1;
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        json_object_put(json_obj);
    }
    
    return response;
}

// Convert natural language to DSL rule
char* convert_natural_language_to_dsl(const char* natural_language, const char* api_key) {
    char prompt[2048];
    snprintf(prompt, sizeof(prompt), 
        "Convert the following natural language security rule to IDS DSL format:\n\n"
        "Natural Language: %s\n\n"
        "Convert to this format: action protocol source_ip source_port direction dest_ip dest_port (options)\n\n"
        "Examples:\n"
        "- 'Alert on SQL injection attempts' -> 'alert tcp any any -> any 80 (msg:\"SQL Injection\"; content:\"' OR 1=1\"; priority:1)'\n"
        "- 'Detect XSS attacks' -> 'alert tcp any any -> any 80 (msg:\"XSS Attack\"; content:\"<script>\"; priority:2)'\n"
        "- 'Monitor port scans' -> 'alert tcp any any -> any any (msg:\"Port Scan\"; content:\"SYN\"; priority:3)'\n\n"
        "Return only the DSL rule, no explanation:",
        natural_language);
    
    AIResponse *response = call_ai_api(prompt, api_key);
    
    if (response && response->success && response->content) {
        // Parse JSON response to extract the rule
        json_object *json_obj = json_tokener_parse(response->content);
        if (json_obj) {
            json_object *choices, *choice, *message, *content;
            if (json_object_object_get_ex(json_obj, "choices", &choices) &&
                json_object_array_length(choices) > 0 &&
                json_object_object_get_ex(json_object_array_get_idx(choices, 0), "message", &message) &&
                json_object_object_get_ex(message, "content", &content)) {
                
                char *rule = strdup(json_object_get_string(content));
                json_object_put(json_obj);
                free(response->content);
                free(response);
                return rule;
            }
            json_object_put(json_obj);
        }
    }
    
    if (response) {
        free(response->content);
        free(response);
    }
    
    return NULL;
}

// Interactive natural language rule creator
void interactive_nlp_rule_creator(const char* api_key) {
    char input[1024];
    char *dsl_rule;
    
    printf("=== Natural Language Rule Creator ===\n");
    printf("Enter security rules in plain English (type 'quit' to exit):\n\n");
    
    while (1) {
        printf("> ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        if (strcmp(input, "quit") == 0) {
            break;
        }
        
        if (strlen(input) == 0) {
            continue;
        }
        
        printf("Converting to DSL rule...\n");
        dsl_rule = convert_natural_language_to_dsl(input, api_key);
        
        if (dsl_rule) {
            printf("Generated DSL Rule: %s\n\n", dsl_rule);
            free(dsl_rule);
        } else {
            printf("Error: Could not convert to DSL rule\n\n");
        }
    }
    
    printf("Goodbye!\n");
}
