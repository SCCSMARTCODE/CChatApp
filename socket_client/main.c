#include "client.h"


int main() {
    clientDetails clientD;
    

    if (setupClient(&clientD) == -1) {
        LOG_ERROR("Client setup failed.");
        return EXIT_FAILURE;
    }

    if (connect(clientD.clientSocketFD, clientD.serverAddress, sizeof(*clientD.serverAddress)) < 0) {
        LOG_ERROR("Failed to connect to server: %s", strerror(errno));
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Successfully connected to the server.");

    if (send(clientD.clientSocketFD, clientD.clientName, sizeof(clientD.clientName), 0) < 0){
        LOG_ERROR("Failed to send user details to server: %s", strerror(errno));
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Successfully sent client details to the server.");

    pthread_t sendThread, receiveThread;

    if (pthread_create(&sendThread, NULL, sendMessages, &clientD) != 0) {
        LOG_ERROR("Failed to create send thread: %s", strerror(errno));
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Send thread created successfully.");

    if (pthread_create(&receiveThread, NULL, receiveMessages, &clientD) != 0) {
        LOG_ERROR("Failed to create receive thread: %s", strerror(errno));

        pthread_cancel(sendThread);
        pthread_join(sendThread, NULL);

        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Receive thread created successfully.");

    pthread_join(sendThread, NULL);
    pthread_join(receiveThread, NULL);

    LOG_INFO("Client shutting down...");
    close(clientD.clientSocketFD);
    free(clientD.clientName);
    free(clientD.serverAddress);
    LOG_SUCCESS("Client shutdown complete.");
    return EXIT_SUCCESS;
}