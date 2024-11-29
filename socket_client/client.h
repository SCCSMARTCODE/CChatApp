#pragma once

#include "../utils/utils.h"


typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
}clientDetails;



int setupClient(clientDetails *clientD);

int setupClient(clientDetails *clientD){
    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1){
        perror("Error: [creating Client Socket Process Failed]\n\n");
        return -1;
    }

    
}