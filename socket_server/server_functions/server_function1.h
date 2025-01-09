#pragma once

#include "../../utils/utils.h"
#define RSA_PUB_KEY_PATH "../socket_server/server_public.pem"
#define RSA_PRI_KEY_PATH "../socket_server/server_private.pem"


typedef struct SecurityKeys{
    RSA *private_key; // RSA format
    char* public_key; // string format
}SecurityKeys;



void manage_encryption_info(SecurityKeys *keys);
void write_rsa_keys();
void load_keys(SecurityKeys *keys);