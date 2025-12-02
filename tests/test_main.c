#include "../include/beb_ll.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple hex decode function */
static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) {
        return 0;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        uint8_t val = 0;

        if (c1 >= '0' && c1 <= '9')
            val = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f')
            val = (c1 - 'a' + 10) << 4;
        else if (c1 >= 'A' && c1 <= 'F')
            val = (c1 - 'A' + 10) << 4;
        else
            return 0;

        if (c2 >= '0' && c2 <= '9')
            val |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f')
            val |= (c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F')
            val |= (c2 - 'A' + 10);
        else
            return 0;

        out[i] = val;
    }

    return hex_len / 2;
}

/* Simple hex encode function */
static void hex_encode(const uint8_t *data, size_t len, char *out) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex_chars[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* Compare two byte arrays */
static bool bytes_equal(const uint8_t *a, size_t a_len, const uint8_t *b,
                        size_t b_len) {
    if (a_len != b_len)
        return false;
    return memcmp(a, b, a_len) == 0;
}

/* Test basic XOR function */
static int test_xor(void) {
    printf("Testing XOR function...\n");

    uint8_t a[32] = {0};
    uint8_t b[32] = {0};
    uint8_t out[32];

    /* Test: 0 XOR 0 = 0 */
    beb_ll_xor(a, b, out);
    if (!bytes_equal(out, 32, a, 32)) {
        printf("  FAIL: 0 XOR 0\n");
        return 1;
    }

    /* Test: all 1s XOR all 0s = all 1s */
    memset(a, 0xff, 32);
    memset(b, 0, 32);
    beb_ll_xor(a, b, out);
    if (!bytes_equal(out, 32, a, 32)) {
        printf("  FAIL: 0xFF XOR 0\n");
        return 1;
    }

    printf("  PASS\n");
    return 0;
}

/* Test content metadata parsing */
static int test_content_metadata(void) {
    printf("Testing content metadata parsing...\n");

    /* Test None */
    uint8_t none_bytes[] = {0};
    size_t offset;
    beb_content_t content;
    beb_ll_error_t err = beb_ll_parse_content_metadata(
        none_bytes, sizeof(none_bytes), &offset, &content);
    if (err != BEB_LL_ERROR_OK || content.type != BEB_CONTENT_NONE ||
        offset != 1) {
        printf("  FAIL: None content\n");
        return 1;
    }

    /* Test BIP380 */
    uint8_t bip380_bytes[] = {2, 0x01, 0x7c};
    err = beb_ll_parse_content_metadata(bip380_bytes, sizeof(bip380_bytes),
                                        &offset, &content);
    if (err != BEB_LL_ERROR_OK || content.type != BEB_CONTENT_BIP380 ||
        offset != 3) {
        printf("  FAIL: BIP380 content\n");
        return 1;
    }

    /* Test proprietary */
    uint8_t prop_bytes[] = {3, 0xde, 0xad, 0xbe};
    err = beb_ll_parse_content_metadata(prop_bytes, sizeof(prop_bytes), &offset,
                                        &content);
    if (err != BEB_LL_ERROR_OK || content.type != BEB_CONTENT_PROPRIETARY ||
        offset != 4) {
        printf("  FAIL: Proprietary content\n");
        beb_ll_content_free(&content);
        return 1;
    }
    beb_ll_content_free(&content);

    printf("  PASS\n");
    return 0;
}

/* Test VarInt encoding/decoding */
static int test_varint(void) {
    printf("Testing VarInt encoding/decoding...\n");

    uint8_t buffer[9];
    size_t written;
    uint64_t value;
    size_t offset;

    /* Test small value (< 0xfd) */
    beb_ll_error_t err = beb_ll_varint_encode(0x42, buffer, sizeof(buffer),
                                              &written);
    if (err != BEB_LL_ERROR_OK || written != 1 || buffer[0] != 0x42) {
        printf("  FAIL: Small VarInt encode\n");
        return 1;
    }

    offset = 0;
    err = beb_ll_varint_decode(buffer, sizeof(buffer), &offset, &value);
    if (err != BEB_LL_ERROR_OK || value != 0x42 || offset != 1) {
        printf("  FAIL: Small VarInt decode\n");
        return 1;
    }

    /* Test medium value (0xfd - 0xffff) */
    err = beb_ll_varint_encode(0x1234, buffer, sizeof(buffer), &written);
    if (err != BEB_LL_ERROR_OK || written != 3 || buffer[0] != 0xfd) {
        printf("  FAIL: Medium VarInt encode\n");
        return 1;
    }

    offset = 0;
    err = beb_ll_varint_decode(buffer, sizeof(buffer), &offset, &value);
    if (err != BEB_LL_ERROR_OK || value != 0x1234 || offset != 3) {
        printf("  FAIL: Medium VarInt decode\n");
        return 1;
    }

    printf("  PASS\n");
    return 0;
}

int main(int argc, char **argv) {
    printf("BEB LL Test Suite\n");
    printf("=================\n\n");

    int failures = 0;

    failures += test_xor();
    failures += test_content_metadata();
    failures += test_varint();

    printf("\n");
    if (failures == 0) {
        printf("All tests PASSED\n");
        return 0;
    } else {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
}
