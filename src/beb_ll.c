#include "../include/beb_ll.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>

/* Memory management functions */
void beb_ll_derivation_paths_free(beb_derivation_path_t *paths, size_t count) {
    if (paths) {
        for (size_t i = 0; i < count; i++) {
            free(paths[i].children);
        }
        free(paths);
    }
}

void beb_ll_secrets_free(beb_secret_t *secrets, size_t count) {
    if (secrets) {
        free(secrets);
    }
}

void beb_ll_decode_v1_result_free(beb_decode_v1_result_t *result) {
    if (result) {
        beb_ll_derivation_paths_free(result->paths, result->paths_count);
        beb_ll_secrets_free(result->individual_secrets, result->secrets_count);
        if (result->cyphertext) {
            free(result->cyphertext);
        }
        memset(result, 0, sizeof(beb_decode_v1_result_t));
    }
}

void beb_ll_decrypt_result_free(beb_decrypt_result_t *result) {
    if (result) {
        beb_ll_content_free(&result->content);
        if (result->data) {
            free(result->data);
        }
        memset(result, 0, sizeof(beb_decrypt_result_t));
    }
}

/* Comparison function for pubkeys */
static int compare_pubkeys(const void *a, const void *b) {
    return memcmp(((const beb_pubkey_t *)a)->data, ((const beb_pubkey_t *)b)->data, 33);
}

/* Check if pubkey is BIP341 NUMS point */
static bool is_bip341_nums(const beb_pubkey_t *key) {
    return memcmp(key->data, BEB_BIP341_NUMS_PUBKEY, 33) == 0;
}

beb_ll_error_t beb_ll_encrypt_aes_gcm_256_v1_with_nonce(
    const beb_derivation_path_t *derivation_paths,
    size_t derivation_paths_count,
    const beb_content_t *content_metadata,
    const beb_pubkey_t *keys,
    size_t keys_count,
    const uint8_t *data,
    size_t data_len,
    const uint8_t nonce[12],
    uint8_t **out,
    size_t *out_len
) {
    /* Filter out BIP341 NUMS and duplicates, then sort */
    beb_pubkey_t *filtered_keys = malloc(sizeof(beb_pubkey_t) * keys_count);
    if (!filtered_keys) {
        return BEB_LL_ERROR_ENCRYPT;
    }
    
    size_t filtered_count = 0;
    for (size_t i = 0; i < keys_count; i++) {
        if (!is_bip341_nums(&keys[i])) {
            /* Check for duplicates */
            bool found = false;
            for (size_t j = 0; j < filtered_count; j++) {
                if (memcmp(filtered_keys[j].data, keys[i].data, 33) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                filtered_keys[filtered_count++] = keys[i];
            }
        }
    }
    
    if (filtered_count == 0 || filtered_count > 255) {
        free(filtered_keys);
        return BEB_LL_ERROR_KEY_COUNT;
    }
    
    /* Sort keys */
    qsort(filtered_keys, filtered_count, sizeof(beb_pubkey_t), compare_pubkeys);
    
    /* Filter and sort derivation paths (remove duplicates) */
    beb_derivation_path_t *filtered_paths = NULL;
    size_t filtered_paths_count = 0;
    
    if (derivation_paths_count > 0) {
        filtered_paths = malloc(sizeof(beb_derivation_path_t) * derivation_paths_count);
        if (!filtered_paths) {
            free(filtered_keys);
            return BEB_LL_ERROR_DERIV_PATH_COUNT;
        }
        
        for (size_t i = 0; i < derivation_paths_count; i++) {
            /* Check for duplicates */
            bool found = false;
            for (size_t j = 0; j < filtered_paths_count; j++) {
                if (filtered_paths[j].count == derivation_paths[i].count &&
                    memcmp(filtered_paths[j].children, derivation_paths[i].children,
                           sizeof(uint32_t) * derivation_paths[i].count) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                /* Copy path */
                filtered_paths[filtered_paths_count].count = derivation_paths[i].count;
                filtered_paths[filtered_paths_count].children = malloc(sizeof(uint32_t) * derivation_paths[i].count);
                if (!filtered_paths[filtered_paths_count].children) {
                    /* Free already allocated paths */
                    for (size_t k = 0; k < filtered_paths_count; k++) {
                        free(filtered_paths[k].children);
                    }
                    free(filtered_paths);
                    free(filtered_keys);
                    return BEB_LL_ERROR_DERIV_PATH_COUNT;
                }
                memcpy(filtered_paths[filtered_paths_count].children, derivation_paths[i].children,
                       sizeof(uint32_t) * derivation_paths[i].count);
                filtered_paths_count++;
            }
        }
    }
    
    if (filtered_paths_count > 255) {
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return BEB_LL_ERROR_DERIV_PATH_COUNT;
    }
    
    /* Validate data length */
    if (data_len == 0 || data_len > UINT32_MAX) {
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return BEB_LL_ERROR_DATA_LENGTH;
    }
    
    /* Encode content metadata */
    uint8_t *content_bytes = NULL;
    size_t content_len = 0;
    beb_ll_error_t err = beb_ll_encode_content(content_metadata, &content_bytes, &content_len);
    if (err != BEB_LL_ERROR_OK) {
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    if (content_len == 0) {
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return BEB_LL_ERROR_CONTENT_METADATA;
    }
    
    /* Compute decryption secret */
    uint8_t secret[32];
    err = beb_ll_decryption_secret(filtered_keys, filtered_count, secret);
    if (err != BEB_LL_ERROR_OK) {
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Generate individual secrets */
    beb_secret_t *individual_secrets = NULL;
    size_t individual_secrets_count = 0;
    err = beb_ll_individual_secrets(secret, filtered_keys, filtered_count, &individual_secrets, &individual_secrets_count);
    if (err != BEB_LL_ERROR_OK) {
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Encode derivation paths */
    uint8_t *encoded_paths = NULL;
    size_t encoded_paths_len = 0;
    err = beb_ll_encode_derivation_paths(filtered_paths, filtered_paths_count, &encoded_paths, &encoded_paths_len);
    if (err != BEB_LL_ERROR_OK) {
        beb_ll_secrets_free(individual_secrets, individual_secrets_count);
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Encode individual secrets */
    uint8_t *encoded_secrets = NULL;
    size_t encoded_secrets_len = 0;
    err = beb_ll_encode_individual_secrets(individual_secrets, individual_secrets_count, &encoded_secrets, &encoded_secrets_len);
    if (err != BEB_LL_ERROR_OK) {
        free(encoded_paths);
        beb_ll_secrets_free(individual_secrets, individual_secrets_count);
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Create payload: content_metadata || data */
    size_t payload_len = content_len + data_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        free(encoded_secrets);
        free(encoded_paths);
        beb_ll_secrets_free(individual_secrets, individual_secrets_count);
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return BEB_LL_ERROR_ENCRYPT;
    }
    memcpy(payload, content_bytes, content_len);
    memcpy(payload + content_len, data, data_len);
    
    /* Encrypt payload */
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    err = beb_ll_encrypt_with_nonce(secret, payload, payload_len, nonce, &ciphertext, &ciphertext_len);
    free(payload);
    if (err != BEB_LL_ERROR_OK) {
        free(encoded_secrets);
        free(encoded_paths);
        beb_ll_secrets_free(individual_secrets, individual_secrets_count);
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Encode encrypted payload */
    uint8_t *encrypted_payload = NULL;
    size_t encrypted_payload_len = 0;
    err = beb_ll_encode_encrypted_payload(nonce, ciphertext, ciphertext_len, &encrypted_payload, &encrypted_payload_len);
    free(ciphertext);
    if (err != BEB_LL_ERROR_OK) {
        free(encoded_secrets);
        free(encoded_paths);
        beb_ll_secrets_free(individual_secrets, individual_secrets_count);
        free(content_bytes);
        beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
        free(filtered_keys);
        return err;
    }
    
    /* Encode v1 format */
    err = beb_ll_encode_v1(1, encoded_paths, encoded_paths_len, encoded_secrets, encoded_secrets_len, 1, encrypted_payload, encrypted_payload_len, out, out_len);
    
    /* Cleanup */
    free(encrypted_payload);
    free(encoded_secrets);
    free(encoded_paths);
    beb_ll_secrets_free(individual_secrets, individual_secrets_count);
    free(content_bytes);
    beb_ll_derivation_paths_free(filtered_paths, filtered_paths_count);
    free(filtered_keys);
    
    return err;
}

beb_ll_error_t beb_ll_decrypt_aes_gcm_256_v1(
    const beb_pubkey_t *key,
    const beb_secret_t *individual_secrets,
    size_t individual_secrets_count,
    const uint8_t *cyphertext,
    size_t cyphertext_len,
    const uint8_t nonce[12],
    beb_decrypt_result_t *result_out
) {
    memset(result_out, 0, sizeof(beb_decrypt_result_t));
    
    /* Compute Si = SHA256("BEB_BACKUP_INDIVIDUAL_SECRET" || key) */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, BEB_INDIVIDUAL_SECRET, strlen(BEB_INDIVIDUAL_SECRET));
    SHA256_Update(&ctx, key->data, 33);
    uint8_t si[32];
    SHA256_Final(si, &ctx);
    
    /* Try each individual secret */
    for (size_t i = 0; i < individual_secrets_count; i++) {
        /* Recover secret: S = Ci XOR Si */
        uint8_t secret[32];
        beb_ll_xor(individual_secrets[i].data, si, secret);
        
        /* Try to decrypt */
        uint8_t *plaintext = NULL;
        size_t plaintext_len = 0;
        beb_ll_error_t err = beb_ll_try_decrypt_aes_gcm_256(cyphertext, cyphertext_len, secret, nonce, &plaintext, &plaintext_len);
        if (err == BEB_LL_ERROR_OK && plaintext) {
            /* Parse content metadata */
            size_t offset = 0;
            err = beb_ll_parse_content_metadata(plaintext, plaintext_len, &offset, &result_out->content);
            if (err != BEB_LL_ERROR_OK) {
                free(plaintext);
                continue;
            }
            
            /* Extract data */
            size_t data_len = plaintext_len - offset;
            if (data_len > 0) {
                result_out->data = malloc(data_len);
                if (!result_out->data) {
                    beb_ll_content_free(&result_out->content);
                    free(plaintext);
                    return BEB_LL_ERROR_DECRYPT;
                }
                memcpy(result_out->data, plaintext + offset, data_len);
                result_out->len = data_len;
            }
            
            free(plaintext);
            return BEB_LL_ERROR_OK;
        }
    }
    
    return BEB_LL_ERROR_WRONG_KEY;
}

