#pragma once

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>


#define IP_INPUT_MAX 40 // This extend to manage ipv4 and ipv6(for future implementation)
#define PORT_INPUT_MAX 7
#define CLIENT_NAME_INPUT_MAX 62





typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
}clientDetails;



typedef struct serverDetails{
    int serverSocketFD;
    struct sockaddr *serverAddress;
}serverDetails;



int setupClient(clientDetails *clientD);
int setupServer(serverDetails *serverD);
void *handleOtherOperationsOnSeperateThread(void*);
void *handleNewlyAcceptedClient(void *client_fd_ptr);

void *sendMessages(void *clientD_ptr);
void *receiveMessages(void *clientD_ptr);

int get_socket();
struct sockaddr *get_address();
char *get_client_name();