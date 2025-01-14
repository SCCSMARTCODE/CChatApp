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
#include <openssl/err.h>

#define UNUSED(x) (void)(x)

#define MAX_CLIENTS 200
#define IP_INPUT_MAX 40 // This extend to manage ipv4 and ipv6(for future implementation)
#define PORT_INPUT_MAX 7
#define CLIENT_NAME_INPUT_MAX 62
#define NETWORK_MESSAGE_BUFFER_SIZE 2000
#define AES_KEY_SIZE 32 // 256-bit AES key
#define AES_BLOCK_SIZE 16 // Block size for AES
#define APP_UI_FILE_PATH "../gui/chat_app.glade"


#define LOG_INFO(format, ...)  g_print("[INFO]: " format "\n", ##__VA_ARGS__)
#define LOG_ERROR(format, ...) fprintf(stderr, "[ERROR]: " format "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) g_print("[SUCCESS]: " format "\n", ##__VA_ARGS__)
#define MESSAGE_FORMAT "%s %s"




typedef struct clientDetails{
    int clientSocketFD;
    char *clientName;
    struct sockaddr *serverAddress;
    RSA *public_key;
    const unsigned char *aes_key;
}clientDetails;


typedef struct SecurityKeys{
    RSA *private_key; // RSA format
    char* public_key; // string format
}SecurityKeys;


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
    // unsigned char *client_aes_keyStore[MAX_CLIENTS];
    SecurityKeys *keys;
    
}serverDetails;


typedef struct HNAC{
    int *clientSocketFD;
    int *clientFDStore;
    SecurityKeys *keys;
    unsigned char *client_aes_keyStore[MAX_CLIENTS];
}HNAC;


int setupClient(clientDetails *clientD);
int setupClientFromGUI(clientDetails *clientD, GtkBuilder* builder);
int setupServer(serverDetails *serverD);
void *handleOtherOperationsOnSeperateThread(void*);
void *handleNewlyAcceptedClient(void *);
void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore, unsigned char **client_aes_keyStore);
void cleanup(clientDetails *clientD);
void process_public_key(char *received_key_str, RSA **client_public_key);

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
char *bytes_to_base64_encode(const unsigned char *data, size_t len);
unsigned char *base64_to_bytes_decode(const char *b64_data, size_t *out_len);
unsigned char* decrypt_aes_key(RSA* rsa_private_key, const char* encrypted_aes_key_str);
unsigned char *generate_aes_key(size_t key_size);
char* encrypt_with_aes(const char* plaintext, const unsigned char* aes_key, const unsigned char* iv);
char* decrypt_with_aes(const char* encoded_ciphertext, const unsigned char* aes_key, const unsigned char* iv);
char *sanitize_base64(const char *input);