#include "../include/beb_ll.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

/* Note: For Bitcoin Core integration, replace OpenSSL SHA256 with Bitcoin
 * Core's crypto/sha256.h */

/* SHA256 using OpenSSL (to be replaced with Bitcoin Core's SHA256) */
static void sha256_hash(const uint8_t *data, size_t data_len,
                        uint8_t hash_out[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(hash_out, &ctx);
}

beb_ll_error_t beb_ll_decryption_secret(const beb_pubkey_t *keys,
                                        size_t keys_count,
                                        uint8_t secret_out[32]) {
    if (keys_count == 0 || keys_count > 255) {
        return BEB_LL_ERROR_KEY_COUNT;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    /* Hash the constant string */
    const char *decryption_secret = BEB_DECRYPTION_SECRET;
    SHA256_Update(&ctx, decryption_secret, strlen(decryption_secret));

    /* Hash each key (already sorted by caller) */
    for (size_t i = 0; i < keys_count; i++) {
        SHA256_Update(&ctx, keys[i].data, 33);
    }

    SHA256_Final(secret_out, &ctx);
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_individual_secret(const uint8_t secret[32],
                                        const beb_pubkey_t *key,
                                        uint8_t individual_secret_out[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    /* Hash the constant string */
    const char *individual_secret = BEB_INDIVIDUAL_SECRET;
    SHA256_Update(&ctx, individual_secret, strlen(individual_secret));

    /* Hash the key */
    SHA256_Update(&ctx, key->data, 33);

    uint8_t si[32];
    SHA256_Final(si, &ctx);

    /* XOR secret with si */
    return beb_ll_xor(secret, si, individual_secret_out);
}

beb_ll_error_t beb_ll_individual_secrets(const uint8_t secret[32],
                                         const beb_pubkey_t *keys,
                                         size_t keys_count,
                                         beb_secret_t **secrets_out,
                                         size_t *secrets_count_out) {
    if (keys_count == 0 || keys_count > 255) {
        return BEB_LL_ERROR_KEY_COUNT;
    }

    beb_secret_t *secrets = malloc(sizeof(beb_secret_t) * keys_count);
    if (!secrets) {
        return BEB_LL_ERROR_DECRYPT;
    }

    for (size_t i = 0; i < keys_count; i++) {
        beb_ll_error_t err = beb_ll_individual_secret(secret, &keys[i],
                                                      secrets[i].data);
        if (err != BEB_LL_ERROR_OK) {
            free(secrets);
            return err;
        }
    }

    *secrets_out = secrets;
    *secrets_count_out = keys_count;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_encrypt_with_nonce(const uint8_t secret[32],
                                         const uint8_t *data, size_t data_len,
                                         const uint8_t nonce[12],
                                         uint8_t **ciphertext_out,
                                         size_t *ciphertext_len_out) {
    if (data_len == 0) {
        return BEB_LL_ERROR_EMPTY_BYTES;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return BEB_LL_ERROR_ENCRYPT;
    }

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, secret, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_ENCRYPT;
    }

    /* Allocate output buffer (plaintext + 16 bytes for GCM tag + some extra for
     * Final) */
    size_t out_len = data_len + 16 + EVP_CIPHER_block_size(EVP_aes_256_gcm());
    uint8_t *ciphertext = malloc(out_len);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_ENCRYPT;
    }

    int len;
    int final_len;

    /* Encrypt the data */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, data, (int)data_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_ENCRYPT;
    }

    /* Finalize encryption (in GCM mode this should output 0 bytes, but check
     * anyway) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_ENCRYPT;
    }

    /* Get the authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            ciphertext + len + final_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_ENCRYPT;
    }

    /* Total ciphertext length: encrypted data from Update + any from Final +
     * tag
     */
    /* Note: In GCM mode, Final typically outputs 0 bytes, but we account for it
     */
    size_t total_len = (size_t)len + (size_t)final_len + 16;

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_out = ciphertext;
    *ciphertext_len_out = total_len;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_try_decrypt_aes_gcm_256(const uint8_t *ciphertext,
                                              size_t ciphertext_len,
                                              const uint8_t secret[32],
                                              const uint8_t nonce[12],
                                              uint8_t **plaintext_out,
                                              size_t *plaintext_len_out) {
    if (ciphertext_len < 16) {
        return BEB_LL_ERROR_DECRYPT;
    }

    /* In GCM, last 16 bytes are the tag, rest is encrypted data */
    size_t encrypted_len = ciphertext_len - 16;
    if (encrypted_len == 0) {
        return BEB_LL_ERROR_EMPTY_BYTES;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return BEB_LL_ERROR_DECRYPT;
    }

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, secret, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_DECRYPT;
    }

    /* Allocate output buffer (encrypted_len + block size for potential Final
     * output) */
    size_t plaintext_buf_len = encrypted_len +
                               EVP_CIPHER_block_size(EVP_aes_256_gcm());
    uint8_t *plaintext = malloc(plaintext_buf_len);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_DECRYPT;
    }

    int len;
    int final_len;

    /* Decrypt the data (excluding the tag) */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                          (int)encrypted_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_DECRYPT;
    }

    /* Set the authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)(ciphertext + encrypted_len)) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_DECRYPT;
    }

    /* Finalize decryption and verify tag */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return BEB_LL_ERROR_DECRYPT;
    }

    /* Total plaintext length */
    size_t total_plaintext_len = (size_t)len + (size_t)final_len;

    EVP_CIPHER_CTX_free(ctx);

    *plaintext_out = plaintext;
    *plaintext_len_out = total_plaintext_len;
    return BEB_LL_ERROR_OK;
}
