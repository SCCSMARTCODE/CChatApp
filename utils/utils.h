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


#define MAX_CLIENTS 20
#define IP_INPUT_MAX 40 // This extend to manage ipv4 and ipv6(for future implementation)
#define PORT_INPUT_MAX 7
#define CLIENT_NAME_INPUT_MAX 62
#define NETWORK_MESSAGE_BUFFER_SIZE 200


#define LOG_INFO(format, ...)  printf("[INFO]: " format "\n", ##__VA_ARGS__)
#define LOG_ERROR(format, ...) fprintf(stderr, "[ERROR]: " format "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) printf("[SUCCESS]: " format "\n", ##__VA_ARGS__)
#define MESSAGE_FORMAT "[USER: %s] Message: %s"




typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
}clientDetails;



typedef struct serverDetails{
    int serverSocketFD;
    struct sockaddr *serverAddress;
    int *clientFDStore;
}serverDetails;


typedef struct HNAC{
    int *clientSocketFD;
    int *clientFDStore;
}HNAC;


int setupClient(clientDetails *clientD);
int setupServer(serverDetails *serverD);
void *handleOtherOperationsOnSeperateThread(void*);
void *handleNewlyAcceptedClient(void *);
void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore);

void *sendMessages(void *clientD_ptr);
void *receiveMessages(void *clientD_ptr);

int get_socket();
struct sockaddr *get_address();
char *get_client_name();