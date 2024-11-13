#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>

#define FW_MAX_CMD 255
#define ONE_HUN 100

typedef struct _CmdArg {
    bool is_interactive;
    char port;
} CmdArg;

typedef struct fwRequest {
    char RawCmd[FW_MAX_CMD];
    char Cmd;
    struct fwRequest* pNext;
} FwRequest;

typedef struct _FwRule {
    char rule[FW_MAX_CMD];
    char matchedIPs[100][16];
    int matchedports[100];
    int matchCount;
    struct _FwRule* pNext;
} FwRule;

FwRule firewallrules[100];
int rulecount = 0;
int requestCount = 0;

void run_add_cmd(FwRequest* fwReq, FwRule* fwHead);
void run_del_cmd(FwRequest* fwReq, FwRule* fwHead);
void run_list_rules_cmd(FwRule* fwHead);
void run_check_cmd(FwRequest* fwReq, FwRule* fwHead);

bool is_digit(char ch) {
    return ((ch >= '0') && (ch <= '9'));
}

int powi(int n, int p) {
    int result = 1;
    for(int i = 0; i < p; i++) result *= n;
    return result;
}

FwRequest* requestHistoryHead = NULL;

void add_request_to_history(const char *raw_command) {
    FwRequest* new_request = malloc(sizeof(FwRequest));
    if (new_request == NULL) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    strcpy(new_request->RawCmd, raw_command);
    new_request->pNext = NULL;

    if (requestHistoryHead == NULL) {
        requestHistoryHead = new_request;
    } else {
        FwRequest* current = requestHistoryHead;
        while (current->pNext != NULL) current = current->pNext;
        current->pNext = new_request;
    }
}

bool validate_ip_port(const char* port) {
    if (strchr(port, '-')) {
        char port1[16], port2[16];
        if (sscanf(port, "%15[^-]-%15s", port1, port2) != 2) return false;
        int p1 = atoi(port1), p2 = atoi(port2);
        if (p1 < 0 || p1 > 65535 || p2 < 0 || p2 > 65535 || p1 >= p2) return false;
        return true;
    } else {
        for (int i = 0; port[i] != '\0'; i++) if (!is_digit(port[i])) return false;
        int port_num = atoi(port);
        return (port_num >= 0 && port_num <= 65535);
    }
}

unsigned int ip_to_int(const char* ip) {
    unsigned int a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

bool validate_ip(const char* ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    char reconstructed[16];
    snprintf(reconstructed, sizeof(reconstructed), "%u.%u.%u.%u", a, b, c, d);
    return (strcmp(reconstructed, ip) == 0);
}

bool validate_ip_range(const char* ip1, const char* ip2) {
    if (!validate_ip(ip1) || !validate_ip(ip2)) return false;
    unsigned int ip1_int = ip_to_int(ip1), ip2_int = ip_to_int(ip2);
    return ip1_int < ip2_int;
}

bool process_args(int argc, char** argv, CmdArg* pCmd) {
    if (argc != 2) return false;
    pCmd->is_interactive = false;
    
    if (strcmp(argv[1], "-i") == 0) {
        pCmd->is_interactive = true;
        return true;
    }
    
    // Parse port number
    char* endptr;
    long port = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port > 65535) return false;
    pCmd->port = (int)port;
    return true;
}

void run_list_requests_cmd() {
    FwRequest* current = requestHistoryHead;
    if (current == NULL) {
        printf("No requests in history\n");
        return;
    }
    while (current) {
        printf("%s\n", current->RawCmd);
        current = current->pNext;
    }
}

void run_listen(CmdArg* pCmd) {
    printf("run server listening on port %d\n", pCmd->port);
}

bool is_valid_rule(char* rule) {
    char ip_part[FW_MAX_CMD], port_part[FW_MAX_CMD];
    if (sscanf(rule, "%s %s", ip_part, port_part) != 2) {
        return false;  // Removed printf here
    }
    
    bool ip_valid = true;
    bool port_valid = true;
    
    // Validate IP part
    if (strchr(ip_part, '-')) {
        char ip1[16], ip2[16];
        if (sscanf(ip_part, "%15[^-]-%15s", ip1, ip2) != 2 || !validate_ip_range(ip1, ip2)) {
            ip_valid = false;
        }
    } else {
        if (!validate_ip(ip_part)) {
            ip_valid = false;
        }
    }
    
    // Validate port part
    if (strchr(port_part, '-')) {
        char port1[16], port2[16];
        if (sscanf(port_part, "%15[^-]-%15s", port1, port2) != 2 || 
            !validate_ip_port(port1) || !validate_ip_port(port2) || 
            atoi(port1) >= atoi(port2)) {
            port_valid = false;
        }
    } else {
        if (!validate_ip_port(port_part)) {
            port_valid = false;
        }
    }
    
    if (!ip_valid || !port_valid) {
        printf("Invalid rule\n");
        return false;
    }
    
    return true;
}




void run_add_cmd(FwRequest* fwReq, FwRule* fwHead) {
    char rule[FW_MAX_CMD];
    sscanf(fwReq->RawCmd, "%*s %[^\n]", rule);

    if(is_valid_rule(rule)) {
        FwRule* newRule = (FwRule*)malloc(sizeof(FwRule));
        if(newRule == NULL) {
            printf("Error: Memory allocation failed\n");
            return;
        }

        memset(newRule, 0, sizeof(FwRule));
        strcpy(newRule->rule, rule);
        newRule->matchCount = 0;

        newRule->pNext = fwHead->pNext;
        fwHead->pNext = newRule;

        rulecount++;
        printf("Rule added\n");
    } 
}

void run_del_cmd(FwRequest* fwReq, FwRule* fwHead) {
    char rule[FW_MAX_CMD];
    // Skip the 'D' command character and any leading spaces
    int matched = sscanf(fwReq->RawCmd, "D %[^\n]", rule);
    
    // Check if we successfully extracted a rule
    if (matched != 1) {
        printf("Rule invalid\n");
        return;
    }

    // Remove any trailing whitespace
    int len = strlen(rule);
    while (len > 0 && isspace(rule[len - 1])) {
        rule[len - 1] = '\0';
        len--;
    }

    // First check if the list is empty
    if (fwHead->pNext == NULL) {
        printf("Rule not found\n");
        return;
    }

    // Check if the rule format is valid using existing validation function
    if (!is_valid_rule(rule)) {
        printf("Rule invalid\n");
        return;
    }

    FwRule* prev = fwHead;
    FwRule* current = fwHead->pNext;

    // Search for exact match of the rule
    while (current != NULL) {
        if (strcmp(current->rule, rule) == 0) {
            // Found exact match - delete it
            prev->pNext = current->pNext;
            free(current);
            rulecount--;
            printf("Rule deleted\n");
            return;
        }
        prev = current;
        current = current->pNext;
    }

    // If we get here, no exact match was found
    printf("Rule not found\n");
}





void run_list_rules_cmd(FwRule* fwHead) {
    FwRule* current = fwHead->pNext; // Start from the first actual rule

    // If there are no rules in the list, print a message and return
    if (current == NULL) {
        printf("No rules in firewall\n");
        return;
    }

    // Iterate through each rule
    while (current != NULL) {
        // Print the rule
        printf("Rule: %s\n", current->rule);

        // Create arrays to track unique IPs and ports
        char uniqueIPs[100][16];
        int uniquePorts[100];
        int uniqueCount = 0;

        // Process each match for this rule
        for (int i = 0; i < current->matchCount; i++) {
            bool isDuplicate = false;
            
            // Check if this IP and port combination already exists
            for (int j = 0; j < uniqueCount; j++) {
                if (strcmp(uniqueIPs[j], current->matchedIPs[i]) == 0 && 
                    uniquePorts[j] == current->matchedports[i]) {
                    isDuplicate = true;
                    break;
                }
            }

            // If not a duplicate, add to unique arrays and print
            if (!isDuplicate && uniqueCount < 100) {
                strcpy(uniqueIPs[uniqueCount], current->matchedIPs[i]);
                uniquePorts[uniqueCount] = current->matchedports[i];
                printf("Query: %s %d\n", current->matchedIPs[i], current->matchedports[i]);
                uniqueCount++;
            }
        }

        // Move to the next rule
        current = current->pNext;
    }
}


bool validate_ip_port(const char* port);

void run_check_cmd(FwRequest* fwReq, FwRule* fwHead) {
    char ip[16];
    int port;
    
    // Parse the IP and port from the command
    if (sscanf(fwReq->RawCmd, "C %15s %d", ip, &port) != 2) {
        printf("Invalid rule\n");
        return;
    }

    // Validate IP and port
    char port_str[6];
    sprintf(port_str, "%d", port);
    if (!validate_ip(ip) || !validate_ip_port(port_str)) {
        printf("Invalid rule\n");
        return;
    }

    // If no rules exist, reject the connection
    if (!fwHead || !fwHead->pNext) {
        printf("Connection rejected\n");
        return;
    }

    // Check against existing rules
    FwRule* curr = fwHead->pNext;
    while (curr != NULL) {
        char ruleIP[16], rulePortStr[16];
        int rulePortStart, rulePortEnd;
        unsigned int ruleIPStart, ruleIPEnd, checkIP;

        // Parse the rule (which can be in format "IP PORT" or "IP1-IP2 PORT1-PORT2")
        if (sscanf(curr->rule, "%15s %15s", ruleIP, rulePortStr) == 2) {
            // Check for IP range
            if (strchr(ruleIP, '-')) {
                char ip1[16], ip2[16];
                if (sscanf(ruleIP, "%15[^-]-%15s", ip1, ip2) == 2) {
                    ruleIPStart = ip_to_int(ip1);
                    ruleIPEnd = ip_to_int(ip2);
                    checkIP = ip_to_int(ip);
                    
                    // Check if IP is within the range
                    if (checkIP < ruleIPStart || checkIP > ruleIPEnd) {
                        curr = curr->pNext;
                        continue;
                    }
                }
            } else {
                // Single IP match
                if (strcmp(ip, ruleIP) != 0) {
                    curr = curr->pNext;
                    continue;
                }
            }

            // Check for port range
            if (strchr(rulePortStr, '-')) {
                char port1[16], port2[16];
                if (sscanf(rulePortStr, "%15[^-]-%15s", port1, port2) == 2) {
                    rulePortStart = atoi(port1);
                    rulePortEnd = atoi(port2);
                    
                    // Check if port is within the range
                    if (port < rulePortStart || port > rulePortEnd) {
                        curr = curr->pNext;
                        continue;
                    }
                }
            } else {
                // Single port match
                rulePortStart = atoi(rulePortStr);
                if (port != rulePortStart) {
                    curr = curr->pNext;
                    continue;
                }
            }

            // If we've made it this far, we have a match
            // Store the match in the rule's history
            if (curr->matchCount < 100) {  // Prevent buffer overflow
                strcpy(curr->matchedIPs[curr->matchCount], ip);
                curr->matchedports[curr->matchCount] = port;
                curr->matchCount++;
            }
            printf("Connection accepted\n");
            return;
        }
        curr = curr->pNext;
    }

    // If no matching rule was found
    printf("Connection rejected\n");
}





void run_interactive(CmdArg* pCmd) {
    char line[255];
    FwRule* fwRuleHead = malloc(sizeof(FwRule));
    if (!fwRuleHead) {
        printf("Memory allocation failed\n");
        return;
    }


    memset(fwRuleHead, 0, sizeof(FwRule));

    while (true) {
        fgets(line, sizeof(line), stdin);

        

        line[strcspn(line, "\n")] = 0;  // Remove newline character

        // Add the command to request history
        add_request_to_history(line);  // Call add_request_to_history after reading command

        FwRequest* fwReq = malloc(sizeof(FwRequest));
        if (!fwReq) {
            printf("Memory allocation failed\n");
            continue;
        }

        strcpy(fwReq->RawCmd, line);  // Store the command
        fwReq->Cmd = line[0];         // Command is the first character

        switch (fwReq->Cmd) {
        case 'A':
            run_add_cmd(fwReq, fwRuleHead);
            break;
        case 'D':
            run_del_cmd(fwReq, fwRuleHead);
            break;
        case 'L':
            run_list_rules_cmd(fwRuleHead);
            break;
        case 'R':
            run_list_requests_cmd();   // Call run_list_requests_cmd without parameters
            break;
        case 'C':
            run_check_cmd(fwReq, fwRuleHead);
            break;
        case 'Q':
            while (requestHistoryHead != NULL) {
                FwRequest* temp = requestHistoryHead;
                requestHistoryHead = requestHistoryHead->pNext;
                free(temp);
            }
            free(fwReq);
            free(fwRuleHead);
            exit(0);
        default:
            printf("Illegal request\n");
            break;
        }
        free(fwReq);
    }
}



void handle_client(int client_socket, FwRule* fwRuleHead) {
    char buffer[FW_MAX_CMD] = {0};
    char response[4096] = {0};  // Increased buffer size for longer responses
    
    // Receive command from client
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }
    
    // Null terminate received data
    buffer[bytes_received] = '\0';
    
    // Trim any trailing newlines or carriage returns
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r')) {
        buffer[len-1] = '\0';
        len--;
    }
    
    // Create FwRequest from received command
    FwRequest* fwReq = malloc(sizeof(FwRequest));
    if (!fwReq) {
        const char* error_msg = "Memory allocation failed\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        return;
    }
    
    strcpy(fwReq->RawCmd, buffer);
    fwReq->Cmd = buffer[0];
    fwReq->pNext = NULL;
    
    // Add command to history
    add_request_to_history(buffer);
    
    // Redirect stdout to capture command output
    FILE* original_stdout = stdout;
    FILE* temp = tmpfile();
    if (!temp) {
        const char* error_msg = "Failed to create temporary file\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        free(fwReq);
        close(client_socket);
        return;
    }
    stdout = temp;
    
    // Process the command
    switch (fwReq->Cmd) {
        case 'A':
            run_add_cmd(fwReq, fwRuleHead);
            break;
        case 'D':
            run_del_cmd(fwReq, fwRuleHead);
            break;
        case 'L':
            run_list_rules_cmd(fwRuleHead);
            break;
        case 'R':
            run_list_requests_cmd();
            break;
        case 'C':
            run_check_cmd(fwReq, fwRuleHead);
            break;
        default:
            printf("Illegal request\n");
            break;
    }
    
    // Restore stdout
    fflush(temp);
    stdout = original_stdout;
    
    // Read the entire output from temporary file
    size_t total_bytes = 0;
    fseek(temp, 0, SEEK_SET);
    
    while (total_bytes < sizeof(response) - 1) {
        size_t bytes_read = fread(response + total_bytes, 1, 
                                sizeof(response) - total_bytes - 1, temp);
        if (bytes_read == 0) break;  // End of file or error
        total_bytes += bytes_read;
    }
    
    response[total_bytes] = '\0';
    
    // Remove trailing whitespace while keeping necessary newlines
    len = strlen(response);
    while (len > 0 && isspace(response[len-1])) {
        response[len-1] = '\0';
        len--;
    }
    
    // Ensure response ends with exactly one newline
    if (len > 0 && response[len-1] != '\n') {
        if (len < sizeof(response) - 2) {
            strcat(response, "\n");
        }
    }
    
    // Send response to client
    if (strlen(response) > 0) {
        ssize_t bytes_sent = send(client_socket, response, strlen(response), 0);
        if (bytes_sent < 0) {
            perror("Failed to send response");
        }
    }
    
    // Cleanup
    fclose(temp);
    free(fwReq);
    close(client_socket);
}





void run_server(int port, FwRule* fwRuleHead) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        // Accept client connection
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("accept failed");
            continue;
        }
        
        // Handle client request
        handle_client(client_socket, fwRuleHead);
    }
}







void usage()
{
    printf("server.exe -i or\n server.exe <portnumber>\n");
}

int main(int argc, char** argv) {
    CmdArg cmd;
    
    if (!process_args(argc, argv, &cmd)) {
        usage();
        return -1;
    }
    
    FwRule* fwRuleHead = malloc(sizeof(FwRule));
    if (!fwRuleHead) {
        printf("Memory allocation failed\n");
        return -1;
    }
    memset(fwRuleHead, 0, sizeof(FwRule));
    
    if (cmd.is_interactive) {
        run_interactive(&cmd);
    } else {
        // Run server mode
        run_server(atoi(argv[1]), fwRuleHead);
    }
    
    free(fwRuleHead);
    return 0;
}


