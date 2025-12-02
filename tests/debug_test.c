#include "../include/beb_ll.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    /* Expected ciphertext from test vector */
    const char *ciphertext_hex = "a208315d1be8d22c436e1d994d13a568cca38e";
    const char *nonce_hex = "a1b2c3d4e5f607080910a1b2";
    const char *secret_hex = "752a7552d8aea88ad52cd65ba4d2c1e250cf9f10b12899d9b6253bf391f18190";
    
    uint8_t ciphertext[32];
    uint8_t nonce[12];
    uint8_t secret[32];
    
    size_t ct_len = 0;
    for (size_t i = 0; i < strlen(ciphertext_hex); i += 2) {
        char c1 = ciphertext_hex[i];
        char c2 = ciphertext_hex[i + 1];
        uint8_t val = 0;
        if (c1 >= '0' && c1 <= '9') val = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f') val = (c1 - 'a' + 10) << 4;
        if (c2 >= '0' && c2 <= '9') val |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') val |= (c2 - 'a' + 10);
        ciphertext[ct_len++] = val;
    }
    
    size_t n_len = 0;
    for (size_t i = 0; i < strlen(nonce_hex); i += 2) {
        char c1 = nonce_hex[i];
        char c2 = nonce_hex[i + 1];
        uint8_t val = 0;
        if (c1 >= '0' && c1 <= '9') val = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f') val = (c1 - 'a' + 10) << 4;
        if (c2 >= '0' && c2 <= '9') val |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') val |= (c2 - 'a' + 10);
        nonce[n_len++] = val;
    }
    
    size_t s_len = 0;
    for (size_t i = 0; i < strlen(secret_hex); i += 2) {
        char c1 = secret_hex[i];
        char c2 = secret_hex[i + 1];
        uint8_t val = 0;
        if (c1 >= '0' && c1 <= '9') val = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f') val = (c1 - 'a' + 10) << 4;
        if (c2 >= '0' && c2 <= '9') val |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') val |= (c2 - 'a' + 10);
        secret[s_len++] = val;
    }
    
    printf("Ciphertext length: %zu\n", ct_len);
    printf("Nonce length: %zu\n", n_len);
    printf("Secret length: %zu\n", s_len);
    
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    beb_ll_error_t err = beb_ll_try_decrypt_aes_gcm_256(ciphertext, ct_len, secret, nonce, &plaintext, &plaintext_len);
    
    if (err == BEB_LL_ERROR_OK) {
        printf("Decryption successful!\n");
        printf("Plaintext length: %zu\n", plaintext_len);
        printf("Plaintext bytes: ");
        for (size_t i = 0; i < plaintext_len; i++) {
            printf("%02x ", plaintext[i]);
        }
        printf("\n");
        free(plaintext);
    } else {
        printf("Decryption failed: %s\n", beb_ll_error_string(err));
    }
    
    return 0;
}

