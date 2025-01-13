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

        strcpy(clientName, ui_client_name);
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

int setupClientFromGUI(clientDetails *clientD, GtkBuilder* builder){

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
    gtk_widget_destroy(connection_dialog);
    gtk_widget_hide(connection_dialog);
    UNUSED(response);

    return 0;
}

void connection_dialog_button_handler(GtkWidget* button, CDBHData *pack) {

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

    if (strlen(ip) < 1 || strlen(port_str) < 1 || strlen(username) < 1) {
        LOG_ERROR("All fields are required.");
        return;
    }

    char* endptr;
    errno = 0;

    port = (int)strtol(port_str, &endptr, 10);
    if (*endptr != '\0' && *endptr != '\n') {
        LOG_ERROR("Please input a correct PORT no. eg [ 2000 ]\n");
        return;
    }

    pack->data->serverAddress = get_address(&port, ip);
    pack->data->clientName = get_client_name(username);

    if (connect(pack->data->clientSocketFD, pack->data->serverAddress, sizeof(*(pack->data->serverAddress))) < 0) {
        LOG_ERROR("Failed to connect to server: %s", strerror(errno));
    } else {
        LOG_SUCCESS("Successfully connected to the server.");
        pack->connection_status = TRUE;

        // Emit a response signal to exit the dialog loop
        gtk_dialog_response(GTK_DIALOG(pack->connection_dialog), GTK_RESPONSE_OK);
        gtk_widget_destroy(pack->connection_dialog);
    }

    gtk_dialog_response(GTK_DIALOG(pack->connection_dialog), GTK_RESPONSE_OK);
    gtk_widget_destroy(pack->connection_dialog);
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
        param->keys = ((serverDetails *)serverD)->keys;
        if (pthread_create(&threadId, NULL, handleNewlyAcceptedClient, param) != 0){
            LOG_ERROR("Failed to create the thread to handle new client operation");
            close(*client_fd);
        }
    }
    free(client_fd);
    
}

void *handleNewlyAcceptedClient(void *param) {
    char receivedMessage[100];
    const char *basic_message = "secured Connection to Server is established Successfully\n";
    int clientFd = *(((HNAC *)param)->clientSocketFD);

   

    if (send(clientFd, ((HNAC *)param)->keys->public_key, strlen(((HNAC *)param)->keys->public_key), 0) == -1) {
        LOG_ERROR("sending == [ public-security-key ] == failed");
        close(clientFd);
        return NULL;
    }
    else{
        LOG_SUCCESS("sent == [ public-security-key ] == of size [ %ld ]", strlen(((HNAC *)param)->keys->public_key));
    }

    // get client info
    char encrypted_aes_key_str[NETWORK_MESSAGE_BUFFER_SIZE];
    if (recv(clientFd, encrypted_aes_key_str, sizeof(encrypted_aes_key_str), 0) == -1){
        LOG_ERROR("Failed to recieve AES Key\n");
        close(clientFd);
        return NULL;
    }
    
    unsigned char* decrypted_aes_key = decrypt_aes_key(((HNAC *)param)->keys->private_key, encrypted_aes_key_str);

    // Send a welcome message
    if (send(clientFd, basic_message, strlen(basic_message), 0) == -1) {
        LOG_ERROR("sending welcome message failed");
        close(clientFd);
        return NULL;
    }
    else{
        g_print("Welcome message sent\n");
    }

    // get client info
    char clientUsername[CLIENT_NAME_INPUT_MAX];
    if (recv(clientFd, clientUsername, sizeof(clientUsername), 0) == -1){
        LOG_ERROR("Failed to recieve client details\n");
        close(clientFd);
        return NULL;
    }

    // filling the clientFDStore for client sync
    int x;
    int *clientFDStore = ((HNAC *)param)->clientFDStore;

    for (x = 0; x < MAX_CLIENTS; x++) {
        if (clientFDStore[x] == -1) {
            clientFDStore[x] = clientFd;
            unsigned char* key_ptr = (unsigned char *)malloc(AES_KEY_SIZE);
            if (!key_ptr) {
                LOG_ERROR("Memory allocation failed for client AES key");
                break;
            }
            ((HNAC *)param)->client_aes_keyStore[x] = key_ptr;
            memcpy(key_ptr, decrypted_aes_key, AES_KEY_SIZE);

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
                    if (((HNAC *)param)->client_aes_keyStore[x]) {
                        free(((HNAC *)param)->client_aes_keyStore[x]);
                        ((HNAC *)param)->client_aes_keyStore[x] = NULL;
                    }
                    break;
                }
            }
            break;
        }
        receivedMessage[bytesReceived] = '\0';

        unsigned char iv[16];
        memcpy(iv, receivedMessage, 16);
        // g_print("Verifing Iv");
        // for (size_t i = 0; i < 16; i++) {
        //     printf("%02X ", iv[i]);
        //     if ((i + 1) % 16 == 0) {
        //         printf("\n");
        //     }
        // }

        char* ciphertext = (char*)(receivedMessage + 16);

        char* plaintext = decrypt_with_aes(ciphertext, decrypted_aes_key, iv);
        g_print("%s\n", plaintext);

        broadcastMessage(clientUsername, plaintext, clientFd, clientFDStore, ((HNAC *)param)->client_aes_keyStore);

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
        
    GtkWidget* send_button = GTK_WIDGET(gtk_builder_get_object(pack->builder, "send_button"));

    SMHPack *smh_pack = malloc(sizeof(SMHPack));
    smh_pack->data = pack->data;
    smh_pack->builder = pack->builder;

    g_signal_connect(send_button, "clicked", G_CALLBACK(send_message_handler), smh_pack);

    return NULL;
}

void send_message_handler(GtkWidget *button, SMHPack* pack){

    UNUSED(button);

    GtkWidget* message_entry = GTK_WIDGET(gtk_builder_get_object(pack->builder, "message_entry"));
    

    const char* message = gtk_entry_get_text(GTK_ENTRY(message_entry));
    
    
    if (strlen(message) >= 1){
        add_to_messages_interface(pack->builder, message, TRUE, "YOU");
        unsigned char iv[16];

        RAND_bytes(iv, sizeof(iv));
        // g_print("Verifing Iv");
        // for (size_t i = 0; i < 16; i++) {
        //     printf("%02X ", iv[i]);
        //     if ((i + 1) % 16 == 0) {
        //         printf("\n");
        //     }
        // }

        char* ciphertext = encrypt_with_aes(message, pack->data->aes_key, iv);

        size_t packet_len = sizeof(iv) + strlen(ciphertext);
        unsigned char* packet = malloc(packet_len);
       

        memcpy(packet, iv, sizeof(iv));
        memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));
        g_print("packet[ %s ] === ciphettext[ %s ]\n\n", packet, ciphertext);

        if (send(pack->data->clientSocketFD, packet, packet_len, 0) == -1) {
            pack->status = FALSE;
            LOG_ERROR("Send failed");
        }
        else{
            pack->status = TRUE;
        }
    }
    gtk_entry_set_text(GTK_ENTRY(message_entry), "");

}

void add_to_messages_interface(GtkBuilder* builder, const char* message, gboolean is_sent, char* sender_username) {

    GtkWidget* messages_interface = GTK_WIDGET(gtk_builder_get_object(builder, "messages_interface"));
    if (!messages_interface || !GTK_IS_LIST_BOX(messages_interface)) {
        g_error("Invalid messages_interface!");
        return;
    }

    GtkWidget* row = gtk_list_box_row_new();
    if (!row) {
        g_error("Failed to create GtkListBoxRow!");
        return;
    }

    GtkWidget* message_node = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    if (!message_node) {
        g_error("Failed to create message_node!");
        return;
    }

    GtkWidget* message_label = gtk_label_new(message);
    GtkWidget* username_label = gtk_label_new(sender_username);

    if (!message_label || !username_label) {
        g_error("Failed to create labels!");
        return;
    }

    gtk_widget_set_halign(message_label, GTK_ALIGN_START);
    gtk_widget_set_halign(username_label, GTK_ALIGN_END);

    gtk_box_pack_start(GTK_BOX(message_node), message_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(message_node), username_label, FALSE, FALSE, 0);

    if (is_sent) {
        gtk_widget_set_halign(message_node, GTK_ALIGN_END);
        gtk_widget_set_margin_start(message_node, 50);
    } else {
        gtk_widget_set_halign(message_node, GTK_ALIGN_START);
        gtk_widget_set_margin_end(message_node, 50);
    }

    gtk_container_add(GTK_CONTAINER(row), message_node);
    gtk_list_box_insert(GTK_LIST_BOX(messages_interface), row, -1);

    g_print("About to show all widgets...\n");

    if (GTK_IS_WIDGET(row)) {
        gtk_widget_show_all(row);
    } else {
        g_error("row is invalid before gtk_widget_show_all!");
    }

}





void *receiveMessages(void *clientD_ptr) {
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
        printf("%s\n", buffer);
    }

    return NULL;
}


void *receiveMessagesWithGUI(void *pack) {
    clientDetails *clientD = ((RMWGUI *)pack)->clientD;
    GtkBuilder* builder = ((RMWGUI *)pack)->builder;
    char buffer[NETWORK_MESSAGE_BUFFER_SIZE];
    ssize_t bytesReceived;
    char sender_username[CLIENT_NAME_INPUT_MAX];
    char message[CLIENT_NAME_INPUT_MAX];

    clientD->public_key = NULL;

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

        if (clientD->public_key){
            // only recieve message if security is available
            int i = 0;        
            // extracting username and message from buffer pack
            while (buffer[i] != ' ' && buffer[i] != '\0') {
                sender_username[i] = buffer[i];
                i++;
            }
            sender_username[i] = '\0';

            i++;
            int j = 0;
            while (buffer[i] != '\0') {
                message[j] = buffer[i];
                i++;
                j++;
            }
            message[j] = '\0';

            // extracting the iv from the message
            unsigned char iv[16];
            memcpy(iv, message, 16);
            char* ciphertext = (char*)(message + 16);

            char *decrypted_message = decrypt_with_aes(ciphertext, clientD->aes_key, iv);

            add_to_messages_interface(builder, decrypted_message, FALSE, sender_username);
        }
        else{
            g_print("Public key trying to sync\n");
            process_public_key(buffer, &clientD->public_key);
            if (clientD->public_key){
                g_print("Public Key synced...\n");
                LOG_SUCCESS("recieved == [ public-security-key ] == of size [ %ld ]", strlen(buffer));
                // g_print("%s\n", buffer);

                // generate the AES_key and send it to the server
                unsigned char *aes_key = generate_aes_key(AES_KEY_SIZE);
                // g_print("AES key: ");
                
                clientD->aes_key = aes_key;
                unsigned char encrypted_aes_key[RSA_size(clientD->public_key)];
                int encrypted_key_len = RSA_public_encrypt(
                    AES_KEY_SIZE,
                    aes_key,
                    encrypted_aes_key,
                    clientD->public_key,
                    RSA_PKCS1_OAEP_PADDING
                );

                // for (size_t i = 0; i < AES_KEY_SIZE; i++) {
                //     g_print("%02X ", encrypted_aes_key[i]);
                // }
                // g_print("\n");

                if (encrypted_key_len == -1) {
                    fprintf(stderr, "Error encrypting AES key: %s\n", ERR_error_string(ERR_get_error(), NULL));
                    exit(EXIT_FAILURE);
                }

                char *b64_encoded_key = bytes_to_base64_encode(encrypted_aes_key, encrypted_key_len);
                // g_print("AES_key [ %s ]\n", b64_encoded_key);

                if (send(clientD->clientSocketFD, b64_encoded_key, strlen(b64_encoded_key), 0) == -1) {
                    LOG_ERROR("Sending AES_key failed");
                    exit(EXIT_FAILURE);
                }

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

            // send client username
             if (send(clientD->clientSocketFD, clientD->clientName, sizeof(clientD->clientName), 0) < 0){
                LOG_ERROR("Failed to send user details to server: %s", strerror(errno));
                close(clientD->clientSocketFD);
                free(clientD->clientName);
                free(clientD->serverAddress);
                return NULL;
            }
            LOG_SUCCESS("Successfully sent client details to the server.");
            
        }

        
    }

    return NULL;
}

void process_public_key(char *received_key_str, RSA **client_public_key){
    // client_public_key = (RSA *)malloc(sizeof(RSA));
    BIO *bio = BIO_new_mem_buf(received_key_str, -1); // Create a BIO from the string

    *client_public_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!*client_public_key) {
        fprintf(stderr, "Error reconstructing public key\n");
        exit(EXIT_FAILURE);
    }
}


void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore, unsigned char **client_aes_keyStore) {
    char formatted_message[NETWORK_MESSAGE_BUFFER_SIZE];
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));


    

    for (int x = 0; x < MAX_CLIENTS; x++) {
        if (clientFDStore[x] != currentClientFD && clientFDStore[x] != -1) {
            char* ciphertext = encrypt_with_aes(receivedMessage, client_aes_keyStore[x], iv);
            
            size_t packet_len = sizeof(iv) + strlen(ciphertext);
            char* packet = malloc(packet_len);
            memcpy(packet, iv, sizeof(iv));
            memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));

            snprintf(formatted_message, sizeof(formatted_message), MESSAGE_FORMAT, clientUsername, packet);

            if (send(clientFDStore[x], formatted_message, strlen(formatted_message), 0) < 0) {
                printf("Failed to send message to %d", clientFDStore[x]);
            }
        }
    }
}


void cleanup(clientDetails *clientD) {
    if (clientD->clientSocketFD > 0) close(clientD->clientSocketFD);
    if (clientD->clientName) free(clientD->clientName);
    if (clientD->serverAddress) free(clientD->serverAddress);
}


int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

unsigned char *generate_aes_key(size_t key_size) {
    unsigned char *key = malloc(key_size);
    if (!key || !RAND_bytes(key, key_size)) {
        fprintf(stderr, "Error generating AES key\n");
        exit(EXIT_FAILURE);
    }
    return key;
}

char *bytes_to_base64_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char *b64_encoded = malloc(bptr->length + 1);
    memcpy(b64_encoded, bptr->data, bptr->length);
    b64_encoded[bptr->length] = '\0';

    BIO_free_all(b64);
    return b64_encoded;
}

unsigned char *base64_to_bytes_decode(const char *b64_data, size_t *out_len) {
    char *sanitized_b64 = sanitize_base64(b64_data);
    if (!sanitized_b64) {
        fprintf(stderr, "Sanitization failed\n");
        return NULL;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(sanitized_b64, -1);
    b64 = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    size_t max_decoded_len = strlen(sanitized_b64) * 3 / 4;
    unsigned char *decoded_data = malloc(max_decoded_len);
    if (!decoded_data) {
        fprintf(stderr, "Memory allocation failed\n");
        BIO_free_all(b64);
        free(sanitized_b64);
        return NULL;
    }

    int decoded_len = BIO_read(b64, decoded_data, max_decoded_len);
    if (decoded_len < 0) {
        fprintf(stderr, "Base64 decoding failed\n");
        free(decoded_data);
        BIO_free_all(b64);
        free(sanitized_b64);
        return NULL;
    }

    *out_len = decoded_len;

    BIO_free_all(b64);
    free(sanitized_b64);

    // Debugging: Print decoded key as hex
    // g_print("Decoded AES key: ");
    // for (size_t i = 0; i < *out_len; i++) {
    //     g_print("%02X ", decoded_data[i]);
    // }
    // g_print("\n");

    return decoded_data;
}


char *sanitize_base64(const char *input) {
    size_t len = strlen(input);
    char *sanitized = malloc(len + 1);
    if (!sanitized) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (input[i] != '\n' && input[i] != '\r' && input[i] != ' ') {
            sanitized[j++] = input[i];
        }
    }
    sanitized[j] = '\0';
    // g_print("\n\nAES_key [ %s ]\n", sanitized);
    return sanitized;
}



unsigned char* decrypt_aes_key(RSA* rsa_private_key, const char* encrypted_aes_key_str) {
    if (!rsa_private_key || !encrypted_aes_key_str) {
        fprintf(stderr, "Invalid input to decrypt_aes_key\n");
        return NULL;
    }
    // g_print("\n\nAES_key [ %s ]\n", encrypted_aes_key_str);
    // Decode Base64 string back to binary
    size_t encrypted_len;
    unsigned char* encrypted_aes_key = base64_to_bytes_decode(encrypted_aes_key_str, &encrypted_len);
    if (!encrypted_aes_key) {
        fprintf(stderr, "Failed to decode encrypted AES key from Base64\n");
        return NULL;
    }

    // if (encrypted_len != AES_KEY_SIZE) {
    //     fprintf(stderr, "Decoded AES key size (%zu) does not match expected size (%d)\n", encrypted_len, AES_KEY_SIZE);
    //     free(encrypted_aes_key);
    //     return NULL;
    // }

    // Allocate buffer for decrypted AES key
    size_t rsa_size = RSA_size(rsa_private_key);
    unsigned char* decrypted_aes_key = malloc(rsa_size);
    if (!decrypted_aes_key) {
        fprintf(stderr, "Failed to allocate memory for decrypted AES key\n");
        free(encrypted_aes_key);
        return NULL;
    }

    // Decrypt the AES key
    int result = RSA_private_decrypt(
        encrypted_len,
        encrypted_aes_key,
        decrypted_aes_key,
        rsa_private_key,
        RSA_PKCS1_OAEP_PADDING
    );

    free(encrypted_aes_key);

    if (result == -1) {
        fprintf(stderr, "Error decrypting AES key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(decrypted_aes_key);
        return NULL;
    }

    return decrypted_aes_key;
}



char* encrypt_with_aes(const char* plaintext, const unsigned char* aes_key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating encryption context\n");
        return NULL;
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int plaintext_len = strlen(plaintext);
    int ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;

    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error encrypting plaintext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    // Base64 encode the ciphertext
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, ciphertext, total_len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char* encoded_ciphertext = malloc(bptr->length + 1);
    if (!encoded_ciphertext) {
        fprintf(stderr, "Memory allocation failed for encoded ciphertext\n");
        free(ciphertext);
        BIO_free_all(b64);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(encoded_ciphertext, bptr->data, bptr->length);
    encoded_ciphertext[bptr->length] = '\0';

    BIO_free_all(b64);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return encoded_ciphertext;
}


char* decrypt_with_aes(const char* encoded_ciphertext, const unsigned char* aes_key, const unsigned char* iv) {
    if (!encoded_ciphertext || !aes_key || !iv) {
        fprintf(stderr, "Invalid input to decrypt_with_aes\n");
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating decryption context\n");
        return NULL;
    }

    // Decode Base64 ciphertext
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded_ciphertext, -1);
    b64 = BIO_push(b64, mem);

    size_t encoded_len = strlen(encoded_ciphertext);
    unsigned char* ciphertext = malloc(encoded_len); // Allocate enough space for decoding
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        BIO_free_all(b64);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int ciphertext_len = BIO_read(b64, ciphertext, encoded_len);
    BIO_free_all(b64);

    if (ciphertext_len <= 0) {
        fprintf(stderr, "Error decoding Base64 ciphertext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char* plaintext = malloc(ciphertext_len + 1); // Add space for null terminator
    if (!plaintext) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error initializing AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;

    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Error during AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        fprintf(stderr, "Error finalizing AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    plaintext[total_len] = '\0'; // Null-terminate the plaintext

    // Clean up
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return (char*)plaintext;
}
