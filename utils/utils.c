#include "utils.h"


int get_socket(){
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr *get_address(int *ui_port, const char* ui_ip){
    char ip[IP_INPUT_MAX];
    char port_str[PORT_INPUT_MAX];
    int port;

    // g_print("check this ---===>>0 [%d], [%s]", *ui_port, ui_ip);

    if (!(ui_ip && ui_port)){
        printf("Input server IP Address: ");

        if (fgets(ip, IP_INPUT_MAX, stdin) != NULL){
            size_t inputLen = strlen(ip);

            if ((inputLen > 0) && (ip[inputLen-1] == '\n')){
                ip[inputLen-1] = '\0';
            }
            else if(inputLen == 0){
                LOG_ERROR("IP Address buffer is empty\n");
                return NULL;
            }
            else{
                LOG_INFO("Please Input a correct IP Address\n");
                return NULL;
            }
        }
        else{
            LOG_ERROR("Error reading IP Address");
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
                if (*endptr != '\0' && *endptr != '\n'){
                    LOG_ERROR("Please Input a correct PORT no. eg [ 2000 ]\n");
                    return NULL;
                }
            }
            else if(inputLen == 0){
                LOG_INFO("PORT buffer is empty.\n");
            }
            else{
                LOG_ERROR("Please Input a correct PORT no.\n");
                return NULL;
            }
        }
        else{
            LOG_ERROR("Error reading the PORT no..");
            return NULL;
        }

        if (*ip)
            LOG_INFO("Generating Address for IP [ %s ] and PORT [ %d ]...\n\n", ip, port);
        else
            LOG_INFO("Generating Address for IP [ 0.0.0.0 ] and PORT [ %d ]...\n\n", port);
    }
    else{
        size_t i;
        for(i = 0; i < strlen(ui_ip); i++){
            ip[i] = ui_ip[i];
        }
        ip[i] = '\0';
        port = *ui_port;
    }

    // g_print("check this ---===>> [%s], [%d]", ip, port);
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

char *get_client_name(const char* ui_client_name){
    char* clientName = malloc(sizeof(char) * CLIENT_NAME_INPUT_MAX);

    if (!ui_client_name){

        printf("Input your USERNAME name (with %d max character): ", CLIENT_NAME_INPUT_MAX-2);

        if (fgets(clientName, CLIENT_NAME_INPUT_MAX, stdin) != NULL){
            size_t inputLen = strlen(clientName);
            // char* endptr;

            if ((inputLen > 0) && (clientName[inputLen-1] == '\n')){
                clientName[inputLen-1] = '\0';
            }
            else if(inputLen == 0){
                LOG_ERROR("USERNAME buffer is empty.\n");
                free(clientName);
                return NULL;
            }
            else{
                printf("%ld\n", inputLen);
                LOG_INFO("Please Input a valid name\n");
                free(clientName);
                return NULL;
            }
        }
        else{
            LOG_ERROR("Error reading the USERNAME..");
            free(clientName);
            return NULL;
        }
    }
    else{

        strcat(clientName, ui_client_name);
    }
    return clientName;
}



int setupClient(clientDetails *clientD){

    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1){
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    clientD->serverAddress = get_address(NULL, NULL);
    if (clientD->serverAddress == NULL){
        LOG_ERROR("[ generating server address failed ]\n\n");
        return -1;
    }

    clientD->clientName = get_client_name(NULL);
    if (clientD->clientName == NULL){
        LOG_ERROR(" [ getting USERNAME failed ]\n\n");
        return -1;
    }
    return 0;
}

int setupClientFromUi(clientDetails *clientD, GtkBuilder* builder){

    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1){
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    GtkWidget* connection_dialog = GTK_WIDGET(gtk_builder_get_object(builder, "connection_dialog"));
    GtkWidget* connection_dialog_button = GTK_WIDGET(gtk_builder_get_object(builder, "connection_dialog_button"));

    

    CDBHData *pack = (CDBHData *)malloc(sizeof(CDBHData));
    pack->data = clientD;
    pack->builder = builder;
    pack->connection_dialog = connection_dialog;

    g_signal_connect(connection_dialog_button, "clicked", G_CALLBACK(connection_dialog_button_handler), pack);

    gint response = gtk_dialog_run(GTK_DIALOG(connection_dialog));
    UNUSED(response);

    return 0;
}

void connection_dialog_button_handler(GtkWidget* button, CDBHData *pack){

    UNUSED(button);

    GtkWidget* ip_entry;
    GtkWidget* port_entry;
    GtkWidget* user_name_entry;

    ip_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_ip_entry"));
    port_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_port_entry"));
    user_name_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "connection_dialog_username_entry"));

    int port;

    const char* ip = gtk_entry_get_text(GTK_ENTRY(ip_entry));
    const char* port_str = gtk_entry_get_text(GTK_ENTRY(port_entry));
    const char* username = gtk_entry_get_text(GTK_ENTRY(user_name_entry));

    if (strlen(ip) < 1 || strlen(port_str) < 1 || strlen(username) < 1){
        return;
    }

    char* endptr;
    errno = 0;

    port = (int)strtol(port_str, &endptr, 10);
    if (*endptr != '\0' && *endptr != '\n'){
        LOG_ERROR("Please Input a correct PORT no. eg [ 2000 ]\n");
        return;
    }

    pack->data->serverAddress = get_address(&port, ip);
    pack->data->clientName = get_client_name(username);


    if (pack->data->clientName && pack->data->clientSocketFD && pack->data->serverAddress){
        gtk_widget_hide(pack->connection_dialog);
    }
}

int setupServer(serverDetails *serverD){

    serverD->serverSocketFD = get_socket();
    if (serverD->serverSocketFD == -1){
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    serverD->serverAddress = get_address(NULL, NULL);
    if (serverD->serverAddress == NULL){
        LOG_ERROR(" [ generating server address failed ]\n\n");
        return -1;
    }
    serverD->clientFDStore = (int *)malloc(sizeof(int)*MAX_CLIENTS);
    for (int x = 0; x < MAX_CLIENTS; x++){
        serverD->clientFDStore[x] = -1;
    }
    return 0;
}




void *handleOtherOperationsOnSeperateThread(void *serverD){
    int *client_fd = malloc(sizeof(int));
    struct sockaddr clientAddress;
    socklen_t addr_len = sizeof(clientAddress);
    int server_fd = ((serverDetails *)serverD)->serverSocketFD;

    while(1){
        *client_fd = accept(server_fd, &clientAddress, &addr_len);
        if (*client_fd < 0) {
            LOG_ERROR("Accept failed");
            continue;
        }
        LOG_SUCCESS("Client connected.\n");

        pthread_t threadId;
        HNAC *param = (HNAC *)malloc(sizeof(HNAC));
        if (!param) {
            LOG_ERROR("Failed to allocate memory for HNAC structure");
            close(*client_fd);
            continue;
        }
        param->clientSocketFD = client_fd;
        param->clientFDStore = ((serverDetails *)serverD)->clientFDStore;
        if (pthread_create(&threadId, NULL, handleNewlyAcceptedClient, param) != 0){
            LOG_ERROR("Failed to create the thread to handle new client operation");
            close(*client_fd);
        }
    }
    free(client_fd);
    
}

void *handleNewlyAcceptedClient(void *param) {
    char receivedMessage[100];
    const char *basic_message = "Connected to Server Successfully\n";
    int clientFd = *(((HNAC *)param)->clientSocketFD);

    // Send a welcome message
    if (send(clientFd, basic_message, strlen(basic_message), 0) == -1) {
        LOG_ERROR("sending welcome message failed");
        close(clientFd);
        return NULL;
    }

    // get client info
    char clientUsername[CLIENT_NAME_INPUT_MAX];
    if (recv(clientFd, clientUsername, sizeof(clientUsername), 0) == -1){
        LOG_ERROR("Failed to recieve client details");
        close(clientFd);
        return NULL;
    }

    // filling the clientFDStore for client sync
    int x;
    int *clientFDStore = ((HNAC *)param)->clientFDStore;


    for (x = 0; x < MAX_CLIENTS; x++) {
        if (clientFDStore[x] == -1) {
            clientFDStore[x] = clientFd;
            break;
        }
        
    }
    
    // Check if we reached the end of the array without finding a slot
    if (x == MAX_CLIENTS) {
        LOG_INFO("Client FD Store is full; consider increasing MAX_CLIENTS");
    }


    while (1) {
        ssize_t bytesReceived = recv(clientFd, receivedMessage, sizeof(receivedMessage) - 1, 0);

        
        if (bytesReceived < 0) {
            LOG_ERROR("recv failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Client disconnected.\n");
            for (x = 0; x < MAX_CLIENTS; x++) {
                if (((HNAC *)param)->clientFDStore[x] == clientFd) {
                    ((HNAC *)param)->clientFDStore[x] = -1;
                    break;
                }
            }
            break;
        }

        receivedMessage[bytesReceived] = '\0';
        broadcastMessage(clientUsername, receivedMessage, clientFd, clientFDStore);

    }

    close(clientFd);
    return NULL;
}



void *sendMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char message[NETWORK_MESSAGE_BUFFER_SIZE];

    while (1) {
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0;

        if (send(clientD->clientSocketFD, message, strlen(message), 0) == -1) {
            LOG_ERROR("Send failed");
            break;
        }
    }

    return NULL;
}

void *sendMessagesWithGUI(void *pack_ptr) {
    SMData *pack = (SMData *)pack_ptr;
    // char message[NETWORK_MESSAGE_BUFFER_SIZE];

    while (1) {
        
        GtkWidget* send_button = GTK_WIDGET(gtk_builder_get_object(pack->builder, "send_button"));

        SMHPack *smh_pack = malloc(sizeof(SMHPack));
        smh_pack->data = pack->data;
        smh_pack->builder = pack->builder;

        g_signal_connect(send_button, "clicked", G_CALLBACK(send_message_handler), smh_pack);

        if (!(smh_pack->status)) {
            LOG_ERROR("Send failed");
            break;
        }
    }

    return NULL;
}

void send_message_handler(GtkWidget *button, SMHPack* pack){

    UNUSED(button);

    GtkWidget* message_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "message_entry"));

    const char* message = gtk_entry_get_text(GTK_ENTRY(message_entry));

    if (strlen(message) >= 1){
        if (send(pack->data->clientSocketFD, message, strlen(message), 0) == -1) {
            pack->status = FALSE;
        }
    }

}

void *receiveMessages(void *pack_ptr) {
    clientDetails *clientD = (clientDetails *)pack_ptr;
    char buffer[NETWORK_MESSAGE_BUFFER_SIZE];
    ssize_t bytesReceived;

    while (1) {
        bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived < 0) {
            LOG_ERROR("Receive failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Server disconnected.\n");
            break;
        }

        buffer[bytesReceived] = '\0';
        printf("%s\n", buffer);
    }

    return NULL;
}


void *receiveMessagesWithGUI(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char buffer[NETWORK_MESSAGE_BUFFER_SIZE];
    ssize_t bytesReceived;

    while (1) {
        bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived < 0) {
            LOG_ERROR("Receive failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Server disconnected.\n");
            break;
        }

        buffer[bytesReceived] = '\0';
        g_print("%s\n", buffer);
    }

    return NULL;
}


void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore) {
    char formatted_message[NETWORK_MESSAGE_BUFFER_SIZE];

    snprintf(formatted_message, sizeof(formatted_message), MESSAGE_FORMAT, clientUsername, receivedMessage);

    for (int x = 0; x < MAX_CLIENTS; x++) {
        if (clientFDStore[x] != currentClientFD && clientFDStore[x] != -1) {
            if (send(clientFDStore[x], formatted_message, strlen(formatted_message), 0) < 0) {
                printf("Failed to send message to %d", clientFDStore[x]);
            }
        }
    }
}