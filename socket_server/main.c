#include "server.h"


int main(){
    serverDetails serverD;

    if (setupServer(&serverD) == -1){
        perror("[ERROR]: server setup failed\n");
        return 0;
    }

    bind(serverD.serverSocketFD, serverD.serverAddress, sizeof(serverD.serverAddress));
    // listen(serverD.serverSocketFD, SERVER_BACKLOG);

    char instruction[50];

    strcpy(instruction, "keep_running");

    while (strcmp(instruction, "shutdown") != 0) {
        printf("Enter command: ");
        scanf("%49s", instruction);
    }

    char ipStr[IP_INPUT_MAX];
    int port = ntohs(((struct sockaddr_in *)serverD.serverAddress)->sin_port);
    strcpy(ipStr, inet_ntoa(((struct sockaddr_in *)serverD.serverAddress)->sin_addr));

    printf("Shutting down server on [ IP : %s ] [ PORT : %d ]\n", ipStr, port);


    close(serverD.serverSocketFD);
    free(serverD.serverAddress);
    return 0;
}