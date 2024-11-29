#include "client.h"


int main(){
    clientDetails clientD;

    if (setupClient(&clientD) == -1){
        perror("[ERROR]: client setup failed\n");
        return 0;
    }


    close(clientD.clientSocketFD);
    free(clientD.clientName);
    free(clientD.serverAddress);
    return 0;
}