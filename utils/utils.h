#pragma once

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>


#define IP_INPUT_MAX 40 // This extend to manage ipv4 and ipv6(for future implementation)
#define PORT_INPUT_MAX 6
#define CLIENT_NAME_INPUT_MAX 62





typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
}clientDetails;




int setupClient(clientDetails *clientD);
int get_socket();
struct sockaddr *get_address();
char *get_client_name();