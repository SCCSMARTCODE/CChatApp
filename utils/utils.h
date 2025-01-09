#pragma once

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <gtk/gtk.h>


// openssl...
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define UNUSED(x) (void)(x)

#define MAX_CLIENTS 20
#define IP_INPUT_MAX 40 // This extend to manage ipv4 and ipv6(for future implementation)
#define PORT_INPUT_MAX 7
#define CLIENT_NAME_INPUT_MAX 62
#define NETWORK_MESSAGE_BUFFER_SIZE 200
#define APP_UI_FILE_PATH "../gui/chat_app.glade"


#define LOG_INFO(format, ...)  g_print("[INFO]: " format "\n", ##__VA_ARGS__)
#define LOG_ERROR(format, ...) fprintf(stderr, "[ERROR]: " format "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) g_print("[SUCCESS]: " format "\n", ##__VA_ARGS__)
#define MESSAGE_FORMAT "%s %s"




typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
}clientDetails;


typedef struct RMWGUI {
    clientDetails *clientD;
    GtkBuilder* builder;
}RMWGUI;


typedef struct CDBHData{
    clientDetails* data;
    GtkBuilder* builder;
    GtkWidget* connection_dialog;
    gboolean connection_status;
}CDBHData;


typedef struct SMData{
    clientDetails* data;
    GtkBuilder* builder;
}SMData;


typedef struct SMHPack{
    clientDetails* data;
    GtkBuilder* builder;
    gboolean status;
}SMHPack;


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
int setupClientFromGUI(clientDetails *clientD, GtkBuilder* builder);
int setupServer(serverDetails *serverD);
void *handleOtherOperationsOnSeperateThread(void*);
void *handleNewlyAcceptedClient(void *);
void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore);
void cleanup(clientDetails *clientD);

void *sendMessages(void *clientD_ptr);
void *sendMessagesWithGUI(void *pack_ptr);
void *receiveMessages(void *clientD_ptr);
void *receiveMessagesWithGUI(void *clientD_ptr);

int get_socket();
// struct sockaddr *get_address();
struct sockaddr *get_address(int *ui_port, const char* ui_ip);
char *get_client_name(const char* ui_client_name);
// char *get_client_name();


void connection_dialog_button_handler(GtkWidget* button, CDBHData *pack);
void send_message_handler(GtkWidget *button, SMHPack* pack);
void add_to_messages_interface(GtkBuilder* builder, const char* message, gboolean is_sent, char* sender_username);

int file_exists(const char *filename);