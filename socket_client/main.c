#include "client.h"


int main(){
    clientDetails clientD;

    if (setupClient(&clientD) == -1){
        perror("[ERROR]: client setup failed\n");
        return 0;
    }

    pthread_t sendThread, receiveThread;

    if (pthread_create(&sendThread, NULL, sendMessages, &clientD) != 0) {
        perror("Failed to create send thread");
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return 1;
    }

    if (pthread_create(&receiveThread, NULL, receiveMessages, &clientD) != 0) {
        perror("Failed to create receive thread");
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return 1;
    }

    // Wait for both threads to finish
    pthread_join(sendThread, NULL);
    pthread_join(receiveThread, NULL);


    close(clientD.clientSocketFD);
    free(clientD.clientName);
    free(clientD.serverAddress);
    return 0;
}