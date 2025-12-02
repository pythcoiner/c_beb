#include "../include/beb.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

beb_error_t beb_parse_magic_byte(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out) {
    if (bytes_len < BEB_MAGIC_LEN) {
        return BEB_ERROR_MAGIC;
    }

    if (memcmp(bytes, BEB_MAGIC, BEB_MAGIC_LEN) != 0) {
        return BEB_ERROR_MAGIC;
    }

    *offset_out = BEB_MAGIC_LEN;
    return BEB_ERROR_OK;
}

beb_error_t beb_parse_version(const uint8_t *bytes,
                              size_t bytes_len,
                              size_t *offset_out,
                              uint8_t *version_out) {
    if (bytes_len == 0) {
        return BEB_ERROR_VERSION;
    }

    uint8_t version = bytes[0];
    /* Version max is 1 (V1) */
    if (version > 1) {
        return BEB_ERROR_VERSION;
    }

    *version_out = version;
    *offset_out = 1;
    return BEB_ERROR_OK;
}

beb_error_t beb_parse_encryption(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out,
                                 uint8_t *encryption_out) {
    if (bytes_len == 0) {
        return BEB_ERROR_ENCRYPTION;
    }

    *encryption_out = bytes[0];
    *offset_out = 1;
    return BEB_ERROR_OK;
}

beb_error_t beb_parse_derivation_paths(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_derivation_path_t **paths_out,
                                       size_t *paths_count_out) {
    size_t offset = 0;
    beb_error_t err = beb_init_offset(bytes, bytes_len, offset, &offset);
    if (err != BEB_ERROR_OK) {
        return BEB_ERROR_DERIV_PATH_EMPTY;
    }

    /* Allocate initial array (we'll realloc if needed) */
    size_t capacity = 16;
    beb_derivation_path_t *paths = malloc(sizeof(beb_derivation_path_t) *
                                          capacity);
    if (!paths) {
        return BEB_ERROR_DERIV_PATH_COUNT;
    }
    size_t paths_count = 0;

    /* Read count */
    uint8_t count = bytes[offset++];

    if (count != 0) {
        for (uint8_t i = 0; i < count; i++) {
            err = beb_check_offset(offset, bytes, bytes_len);
            if (err != BEB_ERROR_OK) {
                goto error;
            }

            uint8_t child_count = bytes[offset++];
            if (child_count == 0) {
                err = BEB_ERROR_DERIV_PATH_EMPTY;
                goto error;
            }

            /* Check we have enough bytes */
            err = beb_check_offset_lookahead(offset, bytes, bytes_len,
                                             child_count * 4);
            if (err != BEB_ERROR_OK) {
                goto error;
            }

            /* Allocate children array */
            uint32_t *children = malloc(sizeof(uint32_t) * child_count);
            if (!children) {
                err = BEB_ERROR_DERIV_PATH_COUNT;
                goto error;
            }

            for (uint8_t j = 0; j < child_count; j++) {
                uint32_t child = ((uint32_t)bytes[offset] << 24) |
                                 ((uint32_t)bytes[offset + 1] << 16) |
                                 ((uint32_t)bytes[offset + 2] << 8) |
                                 ((uint32_t)bytes[offset + 3]);
                offset += 4;
                children[j] = child;
            }

            /* Add to paths array (resize if needed) */
            if (paths_count >= capacity) {
                capacity *= 2;
                beb_derivation_path_t *new_paths = realloc(
                    paths, sizeof(beb_derivation_path_t) * capacity);
                if (!new_paths) {
                    free(children);
                    err = BEB_ERROR_DERIV_PATH_COUNT;
                    goto error;
                }
                paths = new_paths;
            }

            paths[paths_count].children = children;
            paths[paths_count].count = child_count;
            paths_count++;
        }
    }

    *paths_out = paths;
    *paths_count_out = paths_count;
    *offset_out = offset;
    return BEB_ERROR_OK;

error:
    /* Free allocated paths */
    for (size_t i = 0; i < paths_count; i++) {
        free(paths[i].children);
    }
    free(paths);
    return err;
}

beb_error_t beb_parse_individual_secrets(const uint8_t *bytes,
                                         size_t bytes_len,
                                         size_t *offset_out,
                                         beb_secret_t **secrets_out,
                                         size_t *secrets_count_out) {
    if (bytes_len == 0) {
        return BEB_ERROR_EMPTY_BYTES;
    }

    uint8_t count = bytes[0];
    if (count < 1) {
        return BEB_ERROR_INDIVIDUAL_SECRETS_EMPTY;
    }

    size_t offset = 1;
    beb_error_t err = beb_init_offset(bytes, bytes_len, offset, &offset);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    /* Allocate secrets array */
    beb_secret_t *secrets = malloc(sizeof(beb_secret_t) * count);
    if (!secrets) {
        return BEB_ERROR_INDIVIDUAL_SECRETS_LENGTH;
    }

    /* Use a set-like structure to remove duplicates (simple array for now, will
     * sort later) */
    size_t unique_count = 0;

    for (uint8_t i = 0; i < count; i++) {
        err = beb_check_offset_lookahead(offset, bytes, bytes_len, 32);
        if (err != BEB_ERROR_OK) {
            free(secrets);
            return BEB_ERROR_CORRUPTED;
        }

        beb_secret_t secret;
        memcpy(secret.data, &bytes[offset], 32);
        offset += 32;

        /* Check if already exists (simple linear search) */
        bool found = false;
        for (size_t j = 0; j < unique_count; j++) {
            if (memcmp(secrets[j].data, secret.data, 32) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            secrets[unique_count++] = secret;
        }
    }

    *secrets_out = secrets;
    *secrets_count_out = unique_count;
    *offset_out = offset;
    return BEB_ERROR_OK;
}

beb_error_t beb_parse_encrypted_payload(const uint8_t *bytes,
                                        size_t bytes_len,
                                        size_t *offset_out,
                                        uint8_t nonce_out[12],
                                        uint8_t **cyphertext_out,
                                        size_t *cyphertext_len_out) {
    size_t offset = 0;
    beb_error_t err = beb_init_offset(bytes, bytes_len, offset, &offset);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    /* Read nonce */
    err = beb_check_offset_lookahead(offset, bytes, bytes_len, 12);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    memcpy(nonce_out, &bytes[offset], 12);
    offset += 12;

    /* Read VarInt length */
    uint64_t data_len;
    size_t varint_offset = offset;
    err = beb_varint_decode(bytes, bytes_len, &varint_offset, &data_len);
    if (err != BEB_ERROR_OK) {
        return BEB_ERROR_VARINT;
    }

    size_t varint_size = varint_offset - offset;
    offset = varint_offset;

    /* Check data length is reasonable (max u32) */
    if (data_len > UINT32_MAX) {
        return BEB_ERROR_VARINT;
    }

    /* Read ciphertext */
    err = beb_check_offset_lookahead(offset, bytes, bytes_len,
                                     (size_t)data_len);
    if (err != BEB_ERROR_OK) {
        return BEB_ERROR_CORRUPTED;
    }

    uint8_t *cyphertext = malloc((size_t)data_len);
    if (!cyphertext) {
        return BEB_ERROR_DECRYPT;
    }

    memcpy(cyphertext, &bytes[offset], (size_t)data_len);
    offset += (size_t)data_len;

    *cyphertext_out = cyphertext;
    *cyphertext_len_out = (size_t)data_len;
    *offset_out = offset;
    return BEB_ERROR_OK;
}

beb_error_t beb_decode_version(const uint8_t *bytes,
                               size_t bytes_len,
                               uint8_t *version_out) {
    size_t offset;
    beb_error_t err = beb_parse_magic_byte(bytes, bytes_len, &offset);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    size_t version_offset;
    return beb_parse_version(&bytes[offset], bytes_len - offset,
                             &version_offset, version_out);
}

beb_error_t beb_decode_derivation_paths(const uint8_t *bytes,
                                        size_t bytes_len,
                                        beb_derivation_path_t **paths_out,
                                        size_t *paths_count_out) {
    size_t offset;
    beb_error_t err = beb_parse_magic_byte(bytes, bytes_len, &offset);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    size_t version_offset;
    uint8_t version;
    err = beb_parse_version(&bytes[offset], bytes_len - offset, &version_offset,
                            &version);
    if (err != BEB_ERROR_OK) {
        return err;
    }
    offset += version_offset;

    size_t paths_offset;
    return beb_parse_derivation_paths(&bytes[offset], bytes_len - offset,
                                      &paths_offset, paths_out,
                                      paths_count_out);
}

beb_error_t beb_decode_v1(const uint8_t *bytes,
                          size_t bytes_len,
                          beb_decode_v1_result_t *result_out) {
    memset(result_out, 0, sizeof(beb_decode_v1_result_t));

    size_t offset;
    beb_error_t err = beb_parse_magic_byte(bytes, bytes_len, &offset);
    if (err != BEB_ERROR_OK) {
        return err;
    }

    /* Parse version */
    size_t version_offset;
    uint8_t version;
    err = beb_parse_version(&bytes[offset], bytes_len - offset, &version_offset,
                            &version);
    if (err != BEB_ERROR_OK) {
        return err;
    }
    offset += version_offset;

    /* Parse derivation paths */
    size_t deriv_offset;
    err = beb_parse_derivation_paths(&bytes[offset], bytes_len - offset,
                                     &deriv_offset, &result_out->paths,
                                     &result_out->paths_count);
    if (err != BEB_ERROR_OK) {
        return err;
    }
    offset += deriv_offset;

    /* Parse individual secrets */
    size_t secrets_offset;
    err = beb_parse_individual_secrets(
        &bytes[offset], bytes_len - offset, &secrets_offset,
        &result_out->individual_secrets, &result_out->secrets_count);
    if (err != BEB_ERROR_OK) {
        beb_derivation_paths_free(result_out->paths, result_out->paths_count);
        return err;
    }
    offset += secrets_offset;

    /* Parse encryption */
    size_t encryption_offset;
    err = beb_parse_encryption(&bytes[offset], bytes_len - offset,
                               &encryption_offset,
                               &result_out->encryption_type);
    if (err != BEB_ERROR_OK) {
        beb_derivation_paths_free(result_out->paths, result_out->paths_count);
        beb_secrets_free(result_out->individual_secrets,
                         result_out->secrets_count);
        return err;
    }
    offset += encryption_offset;

    /* Parse encrypted payload */
    size_t payload_offset;
    err = beb_parse_encrypted_payload(
        &bytes[offset], bytes_len - offset, &payload_offset, result_out->nonce,
        &result_out->cyphertext, &result_out->cyphertext_len);
    if (err != BEB_ERROR_OK) {
        beb_derivation_paths_free(result_out->paths, result_out->paths_count);
        beb_secrets_free(result_out->individual_secrets,
                         result_out->secrets_count);
        return err;
    }

    return BEB_ERROR_OK;
}
