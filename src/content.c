#include "../include/beb.h"
#include <stdlib.h>
#include <string.h>

/* Parse backup content metadata prefix into a beb_content_t, updating
 * offset_out. */
beb_error_t beb_parse_content_metadata(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_content_t *content_out) {
    if (bytes_len == 0) {
        return BEB_ERROR_CONTENT_METADATA_EMPTY;
    }

    uint8_t data_len = bytes[0];

    if (data_len == 0) {
        /* None */
        content_out->type = BEB_CONTENT_NONE;
        *offset_out = 1;
        return BEB_ERROR_OK;
    }
    if (data_len == 1) {
        return BEB_ERROR_CONTENT_METADATA;
    }
    if (data_len == 2) {
        /* BIP number */
        if (bytes_len < 3) {
            return BEB_ERROR_CONTENT_METADATA;
        }
        uint16_t bip_number = ((uint16_t)bytes[1] << 8) | (uint16_t)bytes[2];

        if (bip_number == 380) {
            content_out->type = BEB_CONTENT_BIP380;
        } else if (bip_number == 388) {
            content_out->type = BEB_CONTENT_BIP388;
        } else if (bip_number == 329) {
            content_out->type = BEB_CONTENT_BIP329;
        } else {
            content_out->type = BEB_CONTENT_BIP;
            content_out->u.bip_number = bip_number;
        }
        *offset_out = 3;
        return BEB_ERROR_OK;
    }
    if (data_len == 255) {
        return BEB_ERROR_CONTENT_RESERVED;
    } /* Proprietary */
    if (bytes_len < (size_t)data_len + 1) {
        return BEB_ERROR_CONTENT_METADATA;
    }
    size_t end = (size_t)data_len + 1;
    if (end > bytes_len) {
        end = bytes_len;
    }

    content_out->type = BEB_CONTENT_PROPRIETARY;
    content_out->u.proprietary.len = data_len;
    content_out->u.proprietary.data = malloc(data_len);
    if (!content_out->u.proprietary.data) {
        return BEB_ERROR_CONTENT_METADATA;
    }
    memcpy(content_out->u.proprietary.data, &bytes[1], data_len);
    *offset_out = end;
    return BEB_ERROR_OK;
}

/* Encode a beb_content_t into its compact serialized representation. */
beb_error_t beb_encode_content(const beb_content_t *content,
                               uint8_t **out,
                               size_t *out_len) {
    uint8_t *result = NULL;
    size_t len = 0;

    switch (content->type) {
    case BEB_CONTENT_NONE:
        result = malloc(1);
        if (!result) {
            return BEB_ERROR_CONTENT_METADATA;
        }
        result[0] = 0;
        len = 1;
        break;

    case BEB_CONTENT_BIP380:
    case BEB_CONTENT_BIP388:
    case BEB_CONTENT_BIP329:
    case BEB_CONTENT_BIP: {
        uint16_t bip_number = 0;
        if (content->type == BEB_CONTENT_BIP380) {
            bip_number = 380;
        } else if (content->type == BEB_CONTENT_BIP388) {
            bip_number = 388;
        } else if (content->type == BEB_CONTENT_BIP329) {
            bip_number = 329;
        } else {
            bip_number = content->u.bip_number;
        }

        result = malloc(3);
        if (!result) {
            return BEB_ERROR_CONTENT_METADATA;
        }
        result[0] = 2;
        result[1] = (uint8_t)(bip_number >> 8);
        result[2] = (uint8_t)(bip_number & 0xff);
        len = 3;
        break;
    }

    case BEB_CONTENT_PROPRIETARY: {
        size_t data_len = content->u.proprietary.len;
        if (data_len <= 2 || data_len >= 255) {
            return BEB_ERROR_CONTENT_METADATA;
        }

        result = malloc(1 + data_len);
        if (!result) {
            return BEB_ERROR_CONTENT_METADATA;
        }
        result[0] = (uint8_t)data_len;
        memcpy(&result[1], content->u.proprietary.data, data_len);
        len = 1 + data_len;
        break;
    }

    case BEB_CONTENT_UNKNOWN:
    default:
        return BEB_ERROR_CONTENT_METADATA;
    }

    *out = result;
    *out_len = len;
    return BEB_ERROR_OK;
}

void beb_content_free(beb_content_t *content) {
    if (content && content->type == BEB_CONTENT_PROPRIETARY) {
        if (content->u.proprietary.data) {
            free(content->u.proprietary.data);
            content->u.proprietary.data = NULL;
        }
    }
}

/* Return true if content represents a known BIP-defined content type. */
bool beb_content_is_known(const beb_content_t *content) {
    switch (content->type) {
    case BEB_CONTENT_BIP380:
    case BEB_CONTENT_BIP388:
    case BEB_CONTENT_BIP329:
    case BEB_CONTENT_BIP:
        return true;
    case BEB_CONTENT_NONE:
    case BEB_CONTENT_UNKNOWN:
    case BEB_CONTENT_PROPRIETARY:
    default:
        return false;
    }
}
