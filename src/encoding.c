#include "../include/beb_ll.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Comparison function for qsort */
static int compare_uint32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* Comparison function for derivation paths */
static int compare_derivation_paths(const void *a, const void *b) {
    const beb_derivation_path_t *pa = (const beb_derivation_path_t *)a;
    const beb_derivation_path_t *pb = (const beb_derivation_path_t *)b;
    
    size_t min_count = (pa->count < pb->count) ? pa->count : pb->count;
    for (size_t i = 0; i < min_count; i++) {
        if (pa->children[i] < pb->children[i]) return -1;
        if (pa->children[i] > pb->children[i]) return 1;
    }
    if (pa->count < pb->count) return -1;
    if (pa->count > pb->count) return 1;
    return 0;
}

/* Comparison function for secrets (32-byte arrays) */
static int compare_secrets(const void *a, const void *b) {
    return memcmp(((const beb_secret_t *)a)->data, ((const beb_secret_t *)b)->data, 32);
}

beb_ll_error_t beb_ll_encode_derivation_paths(const beb_derivation_path_t *paths, size_t paths_count, uint8_t **out, size_t *out_len) {
    if (paths_count > 255) {
        return BEB_LL_ERROR_DERIV_PATH_LENGTH;
    }
    
    /* Calculate total size needed */
    size_t total_size = 1; /* count byte */
    for (size_t i = 0; i < paths_count; i++) {
        if (paths[i].count > 255) {
            return BEB_LL_ERROR_DERIV_PATH_LENGTH;
        }
        total_size += 1; /* child count byte */
        total_size += paths[i].count * 4; /* 4 bytes per child */
    }
    
    uint8_t *result = malloc(total_size);
    if (!result) {
        return BEB_LL_ERROR_DERIV_PATH_COUNT;
    }
    
    size_t offset = 0;
    result[offset++] = (uint8_t)paths_count;
    
    for (size_t i = 0; i < paths_count; i++) {
        result[offset++] = (uint8_t)paths[i].count;
        for (size_t j = 0; j < paths[i].count; j++) {
            uint32_t child = paths[i].children[j];
            result[offset++] = (uint8_t)(child >> 24);
            result[offset++] = (uint8_t)(child >> 16);
            result[offset++] = (uint8_t)(child >> 8);
            result[offset++] = (uint8_t)(child & 0xff);
        }
    }
    
    *out = result;
    *out_len = total_size;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_encode_individual_secrets(const beb_secret_t *secrets, size_t secrets_count, uint8_t **out, size_t *out_len) {
    if (secrets_count == 0) {
        return BEB_LL_ERROR_INDIVIDUAL_SECRETS_EMPTY;
    }
    if (secrets_count > 255) {
        return BEB_LL_ERROR_INDIVIDUAL_SECRETS_LENGTH;
    }
    
    /* Remove duplicates by sorting and filtering */
    beb_secret_t *sorted = malloc(sizeof(beb_secret_t) * secrets_count);
    if (!sorted) {
        return BEB_LL_ERROR_INDIVIDUAL_SECRETS_LENGTH;
    }
    memcpy(sorted, secrets, sizeof(beb_secret_t) * secrets_count);
    qsort(sorted, secrets_count, sizeof(beb_secret_t), compare_secrets);
    
    /* Count unique secrets */
    size_t unique_count = 1;
    for (size_t i = 1; i < secrets_count; i++) {
        if (memcmp(sorted[i].data, sorted[i-1].data, 32) != 0) {
            unique_count++;
        }
    }
    
    if (unique_count > 255) {
        free(sorted);
        return BEB_LL_ERROR_INDIVIDUAL_SECRETS_LENGTH;
    }
    
    size_t total_size = 1 + (unique_count * 32);
    uint8_t *result = malloc(total_size);
    if (!result) {
        free(sorted);
        return BEB_LL_ERROR_INDIVIDUAL_SECRETS_LENGTH;
    }
    
    result[0] = (uint8_t)unique_count;
    size_t offset = 1;
    
    /* Copy unique secrets */
    memcpy(&result[offset], sorted[0].data, 32);
    offset += 32;
    for (size_t i = 1; i < secrets_count; i++) {
        if (memcmp(sorted[i].data, sorted[i-1].data, 32) != 0) {
            memcpy(&result[offset], sorted[i].data, 32);
            offset += 32;
        }
    }
    
    free(sorted);
    *out = result;
    *out_len = total_size;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_encode_encrypted_payload(const uint8_t nonce[12], const uint8_t *cyphertext, size_t cyphertext_len, uint8_t **out, size_t *out_len) {
    if (cyphertext_len == 0) {
        return BEB_LL_ERROR_CYPHERTEXT_EMPTY;
    }
    
    /* Calculate VarInt size */
    size_t varint_size = beb_ll_varint_encode_size(cyphertext_len);
    size_t total_size = 12 + varint_size + cyphertext_len;
    
    uint8_t *result = malloc(total_size);
    if (!result) {
        return BEB_LL_ERROR_ENCRYPT;
    }
    
    size_t offset = 0;
    
    /* Copy nonce */
    memcpy(&result[offset], nonce, 12);
    offset += 12;
    
    /* Encode VarInt */
    size_t written;
    beb_ll_error_t err = beb_ll_varint_encode(cyphertext_len, &result[offset], varint_size, &written);
    if (err != BEB_LL_ERROR_OK) {
        free(result);
        return err;
    }
    offset += written;
    
    /* Copy ciphertext */
    memcpy(&result[offset], cyphertext, cyphertext_len);
    offset += cyphertext_len;
    
    *out = result;
    *out_len = total_size;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_encode_v1(uint8_t version, const uint8_t *derivation_paths, size_t deriv_paths_len, const uint8_t *individual_secrets, size_t individual_secrets_len, uint8_t encryption, const uint8_t *encrypted_payload, size_t encrypted_payload_len, uint8_t **out, size_t *out_len) {
    size_t total_size = BEB_MAGIC_LEN + 1 + deriv_paths_len + individual_secrets_len + 1 + encrypted_payload_len;
    
    uint8_t *result = malloc(total_size);
    if (!result) {
        return BEB_LL_ERROR_ENCRYPT;
    }
    
    size_t offset = 0;
    
    /* Magic */
    memcpy(&result[offset], BEB_MAGIC, BEB_MAGIC_LEN);
    offset += BEB_MAGIC_LEN;
    
    /* Version */
    result[offset++] = version;
    
    /* Derivation paths */
    memcpy(&result[offset], derivation_paths, deriv_paths_len);
    offset += deriv_paths_len;
    
    /* Individual secrets */
    memcpy(&result[offset], individual_secrets, individual_secrets_len);
    offset += individual_secrets_len;
    
    /* Encryption */
    result[offset++] = encryption;
    
    /* Encrypted payload */
    memcpy(&result[offset], encrypted_payload, encrypted_payload_len);
    offset += encrypted_payload_len;
    
    *out = result;
    *out_len = total_size;
    return BEB_LL_ERROR_OK;
}

