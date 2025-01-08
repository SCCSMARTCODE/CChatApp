#include "server_function1.h"

void manage_encryption_info(){
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Set the public exponent (common value: 65537)
    if (!BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error setting public exponent\n");
        exit(EXIT_FAILURE);
    }

    // Generate RSA key pair (2048-bit)
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "Error generating RSA keys\n");
        exit(EXIT_FAILURE);
    }

    FILE *private_fp = fopen(RSA_PRI_KEY_PATH, "wb");
    if (!private_fp) {
        perror("Failed to open private key file");
        exit(EXIT_FAILURE);
    }
    PEM_write_RSAPrivateKey(private_fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_fp);

    FILE *public_fp = fopen(RSA_PUB_KEY_PATH, "wb");
    if (!public_fp) {
        perror("Failed to open public key file");
        exit(EXIT_FAILURE);
    }
    PEM_write_RSAPublicKey(public_fp, rsa);
    fclose(public_fp);

    printf("RSA keys generated and saved successfully.\n");

    RSA_free(rsa);
    BN_free(bn);
}