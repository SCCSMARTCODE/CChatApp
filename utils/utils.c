#include "utils.h"


int get_socket(){
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr *get_address(){
    char* ip;
    int port;

    // to be continued here
    
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



