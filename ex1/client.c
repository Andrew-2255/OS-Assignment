#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h> 

#define MAX_BUFFER_SIZE 1024

void print_usage() {
    printf("Usage: ./client <hostname> <port> <command>\n");
    printf("Example: ./client localhost 2200 A 147.188.193.15 22\n");
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    
    if (port <= 0 || port > 65535) {
        printf("Error: Invalid port number\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, hostname, &serv_addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(hostname);
        if (he == NULL) {
            printf("Error: Invalid hostname or IP address\n");
            close(sock);
            return 1;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    char command[MAX_BUFFER_SIZE] = "";
    for (int i = 3; i < argc; i++) {
        strcat(command, argv[i]);
        if (i < argc - 1) {
            strcat(command, " ");
        }
    }

    if (send(sock, command, strlen(command), 0) < 0) {
        perror("Send failed");
        close(sock);
        return 1;
    }

    char buffer[MAX_BUFFER_SIZE] = {0};
    ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';  
        printf("%s", buffer);  
    } else if (bytes_received < 0) {
        perror("Receive failed");
    }

    close(sock);
    return 0;
}