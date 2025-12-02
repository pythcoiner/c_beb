#include "../include/beb_ll.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

const char *beb_ll_error_string(beb_ll_error_t error) {
    switch (error) {
    case BEB_LL_ERROR_OK:
        return "OK";
    case BEB_LL_ERROR_KEY_COUNT:
        return "KeyCount";
    case BEB_LL_ERROR_DERIV_PATH_COUNT:
        return "DerivPathCount";
    case BEB_LL_ERROR_DERIV_PATH_LENGTH:
        return "DerivPathLength";
    case BEB_LL_ERROR_DERIV_PATH_EMPTY:
        return "DerivPathEmpty";
    case BEB_LL_ERROR_DATA_LENGTH:
        return "DataLength";
    case BEB_LL_ERROR_ENCRYPT:
        return "Encrypt";
    case BEB_LL_ERROR_DECRYPT:
        return "Decrypt";
    case BEB_LL_ERROR_CORRUPTED:
        return "Corrupted";
    case BEB_LL_ERROR_VERSION:
        return "Version";
    case BEB_LL_ERROR_MAGIC:
        return "Magic";
    case BEB_LL_ERROR_VARINT:
        return "VarInt";
    case BEB_LL_ERROR_WRONG_KEY:
        return "WrongKey";
    case BEB_LL_ERROR_INDIVIDUAL_SECRETS_EMPTY:
        return "IndividualSecretsEmpty";
    case BEB_LL_ERROR_INDIVIDUAL_SECRETS_LENGTH:
        return "IndividualSecretsLength";
    case BEB_LL_ERROR_CYPHERTEXT_EMPTY:
        return "CypherTextEmpty";
    case BEB_LL_ERROR_CYPHERTEXT_LENGTH:
        return "CypherTextLength";
    case BEB_LL_ERROR_CONTENT_METADATA:
        return "ContentMetadata";
    case BEB_LL_ERROR_ENCRYPTION:
        return "Encryption";
    case BEB_LL_ERROR_OFFSET_OVERFLOW:
        return "OffsetOverflow";
    case BEB_LL_ERROR_EMPTY_BYTES:
        return "EmptyBytes";
    case BEB_LL_ERROR_INCREMENT:
        return "Increment";
    case BEB_LL_ERROR_CONTENT_METADATA_EMPTY:
        return "ContentMetadataEmpty";
    case BEB_LL_ERROR_CONTENT_RESERVED:
        return "ContentReserved";
    default:
        return "Unknown";
    }
}

beb_ll_error_t beb_ll_xor(const uint8_t a[32], const uint8_t b[32],
                          uint8_t out[32]) {
    for (size_t i = 0; i < 32; i++) {
        out[i] = a[i] ^ b[i];
    }
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_check_offset(size_t offset, const uint8_t *bytes,
                                   size_t bytes_len) {
    (void)bytes; /* unused parameter */
    if (bytes_len <= offset) {
        return BEB_LL_ERROR_CORRUPTED;
    }
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_check_offset_lookahead(size_t offset,
                                             const uint8_t *bytes,
                                             size_t bytes_len,
                                             size_t lookahead) {
    (void)bytes; /* unused parameter */
    if (lookahead == 0) {
        return BEB_LL_ERROR_INCREMENT;
    }
    /* Check for overflow: offset + lookahead > SIZE_MAX */
    if (lookahead > SIZE_MAX - offset) {
        return BEB_LL_ERROR_INCREMENT;
    }
    size_t target = offset + lookahead;
    if (target == 0) {
        return BEB_LL_ERROR_INCREMENT;
    }
    target -= 1;
    if (bytes_len <= target) {
        return BEB_LL_ERROR_CORRUPTED;
    }
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_init_offset(const uint8_t *bytes, size_t bytes_len,
                                  size_t value, size_t *out) {
    beb_ll_error_t err = beb_ll_check_offset(value, bytes, bytes_len);
    if (err != BEB_LL_ERROR_OK) {
        return err;
    }
    *out = value;
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_increment_offset(const uint8_t *bytes, size_t bytes_len,
                                       size_t offset, size_t incr,
                                       size_t *out) {
    /* Check for overflow: offset + incr > SIZE_MAX */
    if (incr > SIZE_MAX - offset) {
        return BEB_LL_ERROR_OFFSET_OVERFLOW;
    }
    size_t new_offset = offset + incr;
    beb_ll_error_t err = beb_ll_check_offset(new_offset, bytes, bytes_len);
    if (err != BEB_LL_ERROR_OK) {
        return err;
    }
    *out = new_offset;
    return BEB_LL_ERROR_OK;
}

/* VarInt encoding/decoding (Bitcoin consensus format) */
size_t beb_ll_varint_encode_size(uint64_t value) {
    if (value < 0xfd) {
        return 1;
    } else if (value <= 0xffff) {
        return 3;
    } else if (value <= 0xffffffff) {
        return 5;
    } else {
        return 9;
    }
}

beb_ll_error_t beb_ll_varint_encode(uint64_t value, uint8_t *out,
                                    size_t out_len, size_t *written) {
    size_t size = beb_ll_varint_encode_size(value);
    if (out_len < size) {
        return BEB_LL_ERROR_VARINT;
    }

    if (value < 0xfd) {
        out[0] = (uint8_t)value;
        *written = 1;
    } else if (value <= 0xffff) {
        out[0] = 0xfd;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        *written = 3;
    } else if (value <= 0xffffffff) {
        out[0] = 0xfe;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        out[3] = (uint8_t)((value >> 16) & 0xff);
        out[4] = (uint8_t)((value >> 24) & 0xff);
        *written = 5;
    } else {
        out[0] = 0xff;
        out[1] = (uint8_t)(value & 0xff);
        out[2] = (uint8_t)((value >> 8) & 0xff);
        out[3] = (uint8_t)((value >> 16) & 0xff);
        out[4] = (uint8_t)((value >> 24) & 0xff);
        out[5] = (uint8_t)((value >> 32) & 0xff);
        out[6] = (uint8_t)((value >> 40) & 0xff);
        out[7] = (uint8_t)((value >> 48) & 0xff);
        out[8] = (uint8_t)((value >> 56) & 0xff);
        *written = 9;
    }
    return BEB_LL_ERROR_OK;
}

beb_ll_error_t beb_ll_varint_decode(const uint8_t *bytes, size_t bytes_len,
                                    size_t *offset, uint64_t *value) {
    if (bytes_len <= *offset) {
        return BEB_LL_ERROR_VARINT;
    }

    uint8_t first = bytes[*offset];
    if (first < 0xfd) {
        *value = first;
        *offset += 1;
    } else if (first == 0xfd) {
        if (bytes_len < *offset + 3) {
            return BEB_LL_ERROR_VARINT;
        }
        *value = ((uint64_t)bytes[*offset + 1]) |
                 ((uint64_t)bytes[*offset + 2] << 8);
        *offset += 3;
    } else if (first == 0xfe) {
        if (bytes_len < *offset + 5) {
            return BEB_LL_ERROR_VARINT;
        }
        *value = ((uint64_t)bytes[*offset + 1]) |
                 ((uint64_t)bytes[*offset + 2] << 8) |
                 ((uint64_t)bytes[*offset + 3] << 16) |
                 ((uint64_t)bytes[*offset + 4] << 24);
        *offset += 5;
    } else {
        if (bytes_len < *offset + 9) {
            return BEB_LL_ERROR_VARINT;
        }
        *value = ((uint64_t)bytes[*offset + 1]) |
                 ((uint64_t)bytes[*offset + 2] << 8) |
                 ((uint64_t)bytes[*offset + 3] << 16) |
                 ((uint64_t)bytes[*offset + 4] << 24) |
                 ((uint64_t)bytes[*offset + 5] << 32) |
                 ((uint64_t)bytes[*offset + 6] << 40) |
                 ((uint64_t)bytes[*offset + 7] << 48) |
                 ((uint64_t)bytes[*offset + 8] << 56);
        *offset += 9;
    }
    return BEB_LL_ERROR_OK;
}
