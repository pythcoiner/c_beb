#include "../include/beb.h"
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void beb_derivation_paths_free(beb_derivation_path_t *paths, size_t count) {
    if (paths) {
        for (size_t i = 0; i < count; i++) {
            free(paths[i].children);
        }
        free(paths);
    }
}

void beb_decode_v1_result_free(beb_decode_v1_result_t *result) {
    if (result) {
        beb_derivation_paths_free(result->paths, result->paths_count);
        free(result->individual_secrets);
        if (result->cyphertext) {
            free(result->cyphertext);
        }
        memset(result, 0, sizeof(beb_decode_v1_result_t));
    }
}

void beb_decrypt_result_free(beb_decrypt_result_t *result) {
    if (result) {
        beb_content_free(&result->content);
        if (result->data) {
            free(result->data);
        }
        memset(result, 0, sizeof(beb_decrypt_result_t));
    }
}

/* Compare two recipient pubkeys lexicographically by their 33-byte encoding. */
static int compare_pubkeys(const void *a, const void *b) {
    return memcmp(((const beb_pubkey_t *)a)->data,
                  ((const beb_pubkey_t *)b)->data, 33);
}

static bool is_bip341_nums(const beb_pubkey_t *key) {
    return memcmp(key->data, BEB_BIP341_NUMS_PUBKEY, 33) == 0;
}

/* Prepare and sort recipient keys: filter BIP341 NUMS, deduplicate, enforce
 * limits. */
static beb_error_t beb_prepare_keys(const beb_pubkey_t *keys,
                                    size_t keys_count,
                                    beb_pubkey_t **out_keys,
                                    size_t *out_count) {
    beb_pubkey_t *filtered_keys = malloc(sizeof(beb_pubkey_t) * keys_count);
    if (!filtered_keys) {
        return BEB_ERROR_ENCRYPT;
    }

    size_t filtered_count = 0;
    for (size_t i = 0; i < keys_count; i++) {
        if (!is_bip341_nums(&keys[i])) {
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
        return BEB_ERROR_KEY_COUNT;
    }

    qsort(filtered_keys, filtered_count, sizeof(beb_pubkey_t), compare_pubkeys);

    *out_keys = filtered_keys;
    *out_count = filtered_count;
    return BEB_ERROR_OK;
}

static bool
beb_derivation_path_is_duplicate(const beb_derivation_path_t *filtered_paths,
                                 size_t filtered_paths_count,
                                 const beb_derivation_path_t *candidate) {
    for (size_t i = 0; i < filtered_paths_count; i++) {
        if (filtered_paths[i].count == candidate->count &&
            memcmp(filtered_paths[i].children, candidate->children,
                   sizeof(uint32_t) * candidate->count) == 0) {
            return true;
        }
    }
    return false;
}

static beb_error_t beb_derivation_path_copy(beb_derivation_path_t *dst,
                                            const beb_derivation_path_t *src) {
    dst->count = src->count;
    dst->children = malloc(sizeof(uint32_t) * src->count);
    if (!dst->children) {
        return BEB_ERROR_DERIV_PATH_COUNT;
    }

    memcpy(dst->children, src->children, sizeof(uint32_t) * src->count);
    return BEB_ERROR_OK;
}

/* Prepare derivation paths: deduplicate, deep-copy children, and enforce
 * limits. */
static beb_error_t
beb_prepare_derivation_paths(const beb_derivation_path_t *derivation_paths,
                             size_t derivation_paths_count,
                             beb_derivation_path_t **out_paths,
                             size_t *out_count) {
    *out_paths = NULL;
    *out_count = 0;

    /* Fast path: no input derivation paths */
    if (derivation_paths_count == 0) {
        return BEB_ERROR_OK;
    }

    beb_derivation_path_t *filtered_paths = malloc(
        sizeof(beb_derivation_path_t) * derivation_paths_count);
    if (!filtered_paths) {
        return BEB_ERROR_DERIV_PATH_COUNT;
    }

    size_t filtered_paths_count = 0;

    for (size_t i = 0; i < derivation_paths_count; i++) {
        const beb_derivation_path_t *candidate = &derivation_paths[i];

        /* Skip if this path is already present */
        if (beb_derivation_path_is_duplicate(filtered_paths,
                                             filtered_paths_count, candidate)) {
            continue;
        }

        /* Copy path (count + children array) into filtered set */
        beb_error_t err = beb_derivation_path_copy(
            &filtered_paths[filtered_paths_count], candidate);
        if (err != BEB_ERROR_OK) {
            /* Free already allocated paths and their children */
            for (size_t k = 0; k < filtered_paths_count; k++) {
                free(filtered_paths[k].children);
            }
            free(filtered_paths);
            return err;
        }

        filtered_paths_count++;
    }

    if (filtered_paths_count > 255) {
        beb_derivation_paths_free(filtered_paths, filtered_paths_count);
        return BEB_ERROR_DERIV_PATH_COUNT;
    }

    *out_paths = filtered_paths;
    *out_count = filtered_paths_count;
    return BEB_ERROR_OK;
}

/* Encode content metadata and fail if the encoded representation is empty. */
static beb_error_t beb_encode_content_checked(const beb_content_t *content,
                                              uint8_t **out_bytes,
                                              size_t *out_len) {
    uint8_t *content_bytes = NULL;
    size_t content_len = 0;

    beb_error_t err = beb_encode_content(content, &content_bytes, &content_len);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    if (content_len == 0) {
        free(content_bytes);
        return BEB_ERROR_CONTENT_METADATA;
    }

    *out_bytes = content_bytes;
    *out_len = content_len;
    return BEB_ERROR_OK;
}

/* Compute shared decryption secret and per-recipient individual secrets. */
static beb_error_t beb_compute_secrets(const beb_pubkey_t *keys,
                                       size_t keys_count,
                                       uint8_t secret[32],
                                       beb_secret_t **out_individual_secrets,
                                       size_t *out_individual_secrets_count) {
    beb_error_t err = beb_decryption_secret(keys, keys_count, secret);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    beb_secret_t *individual_secrets = NULL;
    size_t individual_secrets_count = 0;
    err = beb_individual_secrets(secret, keys, keys_count, &individual_secrets,
                                 &individual_secrets_count);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    *out_individual_secrets = individual_secrets;
    *out_individual_secrets_count = individual_secrets_count;
    return BEB_ERROR_OK;
}

/* Encode derivation paths and individual secrets into their serialized
 * representations. */
static beb_error_t
beb_encode_paths_and_secrets(const beb_derivation_path_t *paths,
                             size_t paths_count,
                             const beb_secret_t *individual_secrets,
                             size_t individual_secrets_count,
                             uint8_t **out_paths,
                             size_t *out_paths_len,
                             uint8_t **out_secrets,
                             size_t *out_secrets_len) {
    uint8_t *encoded_paths = NULL;
    size_t encoded_paths_len = 0;
    beb_error_t err = beb_encode_derivation_paths(
        paths, paths_count, &encoded_paths, &encoded_paths_len);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    uint8_t *encoded_secrets = NULL;
    size_t encoded_secrets_len = 0;
    err = beb_encode_individual_secrets(individual_secrets,
                                        individual_secrets_count,
                                        &encoded_secrets, &encoded_secrets_len);
    if (err != BEB_ERROR_OK) {
        free(encoded_paths);
        return err;
    }

    *out_paths = encoded_paths;
    *out_paths_len = encoded_paths_len;
    *out_secrets = encoded_secrets;
    *out_secrets_len = encoded_secrets_len;
    return BEB_ERROR_OK;
}

/* Build (content || data), encrypt it, and wrap it into the v1 encrypted
 * payload format. */
static beb_error_t
beb_build_and_encrypt_payload(const uint8_t secret[32],
                              const uint8_t *content_bytes,
                              size_t content_len,
                              const uint8_t *data,
                              size_t data_len,
                              const uint8_t nonce[12],
                              uint8_t **out_encrypted_payload,
                              size_t *out_encrypted_payload_len) {
    size_t payload_len = content_len + data_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        return BEB_ERROR_ENCRYPT;
    }

    memcpy(payload, content_bytes, content_len);
    memcpy(payload + content_len, data, data_len);

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    beb_error_t err = beb_encrypt_with_nonce(
        secret, payload, payload_len, nonce, &ciphertext, &ciphertext_len);
    free(payload);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    uint8_t *encrypted_payload = NULL;
    size_t encrypted_payload_len = 0;
    err = beb_encode_encrypted_payload(nonce, ciphertext, ciphertext_len,
                                       &encrypted_payload,
                                       &encrypted_payload_len);
    free(ciphertext);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    *out_encrypted_payload = encrypted_payload;
    *out_encrypted_payload_len = encrypted_payload_len;
    return BEB_ERROR_OK;
}

/* High-level entry point to create a BEB v1 backup using AES-GCM-256 and an
 * explicit nonce. */
beb_error_t beb_encrypt_aes_gcm_256_v1_with_nonce(
    const beb_derivation_path_t *derivation_paths,
    size_t derivation_paths_count,
    const beb_content_t *content_metadata,
    const beb_pubkey_t *keys,
    size_t keys_count,
    const uint8_t *data,
    size_t data_len,
    const uint8_t nonce[12],
    uint8_t **out,
    size_t *out_len) {
    beb_error_t err = BEB_ERROR_OK;

    /* Validate data length */
    if (data_len == 0 || data_len > UINT32_MAX) {
        return BEB_ERROR_DATA_LENGTH;
    }

    beb_pubkey_t *filtered_keys = NULL;
    size_t filtered_count = 0;

    beb_derivation_path_t *filtered_paths = NULL;
    size_t filtered_paths_count = 0;

    uint8_t *content_bytes = NULL;
    size_t content_len = 0;

    uint8_t secret[32];

    beb_secret_t *individual_secrets = NULL;
    size_t individual_secrets_count = 0;

    uint8_t *encoded_paths = NULL;
    size_t encoded_paths_len = 0;

    uint8_t *encoded_secrets = NULL;
    size_t encoded_secrets_len = 0;

    uint8_t *encrypted_payload = NULL;
    size_t encrypted_payload_len = 0;

    /* Filter, deduplicate and sort recipient keys, excluding BIP341 NUMS */
    err = beb_prepare_keys(keys, keys_count, &filtered_keys, &filtered_count);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Deduplicate and copy derivation paths, enforcing path-count limits */
    err = beb_prepare_derivation_paths(derivation_paths, derivation_paths_count,
                                       &filtered_paths, &filtered_paths_count);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Encode content metadata into a byte buffer and ensure it is non-empty */
    err = beb_encode_content_checked(content_metadata, &content_bytes,
                                     &content_len);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Derive shared decryption secret and per-recipient individual secrets */
    err = beb_compute_secrets(filtered_keys, filtered_count, secret,
                              &individual_secrets, &individual_secrets_count);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Encode derivation paths and individual secrets for inclusion in v1 blob
     */
    err = beb_encode_paths_and_secrets(
        filtered_paths, filtered_paths_count, individual_secrets,
        individual_secrets_count, &encoded_paths, &encoded_paths_len,
        &encoded_secrets, &encoded_secrets_len);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Build (content || data), encrypt with AES-GCM and encode with nonce */
    err = beb_build_and_encrypt_payload(
        secret, content_bytes, content_len, data, data_len, nonce,
        &encrypted_payload, &encrypted_payload_len);
    if (err != BEB_ERROR_OK) {
        goto cleanup;
    }

    /* Wrap metadata, secrets and encrypted payload into BEB v1 container */
    err = beb_encode_v1(1, encoded_paths, encoded_paths_len, encoded_secrets,
                        encoded_secrets_len, 1, encrypted_payload,
                        encrypted_payload_len, out, out_len);

cleanup:
    /* Free temporary encrypted payload buffer */
    free(encrypted_payload);
    /* Free encoded secrets buffer */
    free(encoded_secrets);
    /* Free encoded derivation paths buffer */
    free(encoded_paths);
    /* Free array of individual secrets */
    free(individual_secrets);
    /* Free encoded content metadata buffer */
    free(content_bytes);
    /* Free filtered/copy of derivation paths (and their children arrays) */
    beb_derivation_paths_free(filtered_paths, filtered_paths_count);
    /* Free filtered/sorted copy of recipient keys */
    free(filtered_keys);

    return err;
}
