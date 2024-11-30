#include "utils.h"


int get_socket(){
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr *get_address(){
    char ip[IP_INPUT_MAX];
    char port_str[PORT_INPUT_MAX];
    int port;


    printf("Input server IP Address: ");

    if (fgets(ip, IP_INPUT_MAX, stdin) != NULL){
        size_t inputLen = strlen(ip);

        if ((inputLen > 0) && (ip[inputLen-1] == '\n')){
            ip[inputLen-1] = '\0';
        }
        else if(inputLen == 0){
            perror("IP Address buffer is empty\n");
            return NULL;
        }
        else{
            perror("Please Input a correct IP Address\n");
            return NULL;
        }
    }
    else{
        perror("Error reading IP Address");
        return NULL;
    }




    printf("Input server PORT no: ");

    if (fgets(port_str, PORT_INPUT_MAX, stdin) != NULL){
        size_t inputLen = strlen(port_str);
        char* endptr;

        if ((inputLen > 0) && (port_str[inputLen-1] == '\n')){
            port_str[inputLen-1] = '\0';

            errno = 0;

            port = (int)strtol(port_str, &endptr, 10);
            if (*endptr != '\0'){
                perror("Please Input a correct PORT no. eg [ 2000 ]\n");
                return NULL;
            }
        }
        else if(inputLen == 0){
            perror("PORT buffer is empty.\n");
            // return NULL;
        }
        else{
            perror("Please Input a correct PORT no.\n");
            return NULL;
        }
    }
    else{
        perror("Error reading the PORT no..");
        return NULL;
    }


    printf("Generating Address for IP [ %s ] and PORT [ %d ]...\n\n", ip, port);

    struct sockaddr_in *new_address = malloc(sizeof(struct sockaddr_in));
    new_address->sin_port = htons(port);
    new_address->sin_family = AF_INET;

    if (strlen(ip) == 0){
        new_address->sin_addr.s_addr = INADDR_ANY;
    }
    else{
        inet_pton(AF_INET, ip, &new_address->sin_addr.s_addr);
    }

    return (struct sockaddr *)(new_address);
}

char *get_client_name(){
    char* clientName = malloc(sizeof(char) * CLIENT_NAME_INPUT_MAX);

    printf("Input your USERNAME name (with %d max character): ", CLIENT_NAME_INPUT_MAX-2);

    if (fgets(clientName, CLIENT_NAME_INPUT_MAX, stdin) != NULL){
        size_t inputLen = strlen(clientName);
        char* endptr;

        if ((inputLen > 0) && (clientName[inputLen-1] == '\n')){
            clientName[inputLen-1] = '\0';
        }
        else if(inputLen == 0){
            perror("USERNAME buffer is empty.\n");
            free(clientName);
            return NULL;
        }
        else{
            printf("%ld\n", inputLen);
            perror("Please Input a valid name\n");
            free(clientName);
            return NULL;
        }
    }
    else{
        perror("Error reading the USERNAME..");
        free(clientName);
        return NULL;
    }
    return clientName;
}



int setupClient(clientDetails *clientD){

    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1){
        perror("Error: [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    clientD->serverAddress = get_address();
    if (clientD->serverAddress == NULL){
        perror("Error: [ generating server address failed ]\n\n");
        return -1;
    }

    clientD->clientName = get_client_name();
    if (clientD->clientName == NULL){
        perror("Error: [ getting USERNAME failed ]\n\n");
        return -1;
    }
    return 0;
}



int setupServer(serverDetails *serverD){

    serverD->serverSocketFD = get_socket();
    if (serverD->serverSocketFD == -1){
        perror("Error: [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    serverD->serverAddress = get_address();
    if (serverD->serverAddress == NULL){
        perror("Error: [ generating server address failed ]\n\n");
        return -1;
    }

    return 0;
}

void *handleOtherOperationsOnSeperateThread(void *serverFD){
    int *client_fd = malloc(sizeof(int));
    struct sockaddr clientAddress;
    socklen_t addr_len = sizeof(clientAddress);
    int server_id = *(int *)(serverFD);

    while(1){
        *client_fd = accept(server_id, &clientAddress, &addr_len);
        if (*client_fd < 0) {
            perror("Accept failed");
            free(client_fd);
            continue;
        }
        printf("Client connected.\n");

        pthread_t threadId;
        if (pthread_create(&threadId, NULL, handleNewlyAcceptedClient, client_fd) != 0){
            perror("Failed to create the thread to handle new client operation");
            close(*client_fd);
            free(client_fd);
        }
    }
}

void *handleNewlyAcceptedClient(void *client_fd_ptr) {
    char receivedMessage[100];
    const char *basic_message = "Connection Successful\n";
    int clientFd = *(int *)client_fd_ptr;
    free(client_fd_ptr);

    // Send a welcome message
    if (send(clientFd, basic_message, strlen(basic_message), 0) == -1) {
        perror("send failed");
        close(clientFd);
        return NULL;
    }

    while (1) {
        ssize_t bytesReceived = recv(clientFd, receivedMessage, sizeof(receivedMessage) - 1, 0);
        
        if (bytesReceived < 0) {
            perror("recv failed");
            break;
        } else if (bytesReceived == 0) {
            printf("Client disconnected.\n");
            break;
        }

        receivedMessage[bytesReceived] = '\0';
        printf("Received [ %s ]\n", receivedMessage);
    }

    close(clientFd);
    return NULL;
}



void *sendMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char message[100];

    while (1) {
        printf("Enter message to send: ");
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0;

        if (send(clientD->clientSocketFD, message, strlen(message), 0) == -1) {
            perror("Send failed");
            break;
        }
    }

    return NULL;
}

void *receiveMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char buffer[100];
    ssize_t bytesReceived;

    while (1) {
        bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived < 0) {
            perror("Receive failed");
            break;
        } else if (bytesReceived == 0) {
            printf("Server disconnected.\n");
            break;
        }

        buffer[bytesReceived] = '\0';
        printf("Received: %s\n", buffer);
    }

    return NULL;
}