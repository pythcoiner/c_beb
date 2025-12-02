#include "../include/beb_ll.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple hex decode */
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

/* Simple hex encode */
static void hex_encode(const uint8_t *data, size_t len, char *out) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex_chars[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* Compare byte arrays */
static bool bytes_equal(const uint8_t *a, size_t a_len, const uint8_t *b,
                        size_t b_len) {
    if (a_len != b_len)
        return false;
    return memcmp(a, b, a_len) == 0;
}

/* Test AES-GCM encryption vectors */
static int test_aesgcm256_encryption(void) {
    printf("Testing AES-GCM-256 encryption vectors...\n");

    /* Test case 1: Basic encryption */
    const char *nonce_hex = "000102030405060708090a0b";
    const char *plaintext_hex = "48656c6c6f";
    const char *secret_hex = "0000000000000000000000000000000000000000000000000"
                             "000000000000000";
    const char
        *expected_ciphertext_hex = "c0ae5f3e6f609000697cc7c8de2b30ce8817ca44fa";

    uint8_t nonce[12];
    uint8_t secret[32];
    uint8_t plaintext[16];
    uint8_t expected_ciphertext[32];

    size_t nonce_len = hex_decode(nonce_hex, nonce, sizeof(nonce));
    size_t secret_len = hex_decode(secret_hex, secret, sizeof(secret));
    size_t plaintext_len = hex_decode(plaintext_hex, plaintext,
                                      sizeof(plaintext));
    size_t expected_len = hex_decode(expected_ciphertext_hex,
                                     expected_ciphertext,
                                     sizeof(expected_ciphertext));

    if (nonce_len != 12 || secret_len != 32 || plaintext_len == 0 ||
        expected_len == 0) {
        printf("  FAIL: Invalid test data\n");
        return 1;
    }

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    beb_ll_error_t err = beb_ll_encrypt_with_nonce(
        secret, plaintext, plaintext_len, nonce, &ciphertext, &ciphertext_len);

    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: Encryption failed: %s\n", beb_ll_error_string(err));
        return 1;
    }

    if (!bytes_equal(ciphertext, ciphertext_len, expected_ciphertext,
                     expected_len)) {
        printf("  FAIL: Ciphertext mismatch\n");
        char got_hex[256];
        char exp_hex[256];
        hex_encode(ciphertext, ciphertext_len < 128 ? ciphertext_len : 128,
                   got_hex);
        hex_encode(expected_ciphertext, expected_len < 128 ? expected_len : 128,
                   exp_hex);
        printf("    Got:      %s\n", got_hex);
        printf("    Expected: %s\n", exp_hex);
        free(ciphertext);
        return 1;
    }

    /* Test decryption */
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    err = beb_ll_try_decrypt_aes_gcm_256(ciphertext, ciphertext_len, secret,
                                         nonce, &decrypted, &decrypted_len);

    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: Decryption failed: %s\n", beb_ll_error_string(err));
        free(ciphertext);
        return 1;
    }

    if (!bytes_equal(decrypted, decrypted_len, plaintext, plaintext_len)) {
        printf("  FAIL: Decrypted plaintext mismatch\n");
        free(ciphertext);
        free(decrypted);
        return 1;
    }

    free(ciphertext);
    free(decrypted);

    /* Test case 2: Empty plaintext should fail */
    err = beb_ll_encrypt_with_nonce(secret, NULL, 0, nonce, &ciphertext,
                                    &ciphertext_len);
    if (err == BEB_LL_ERROR_OK) {
        printf("  FAIL: Empty plaintext should fail\n");
        if (ciphertext)
            free(ciphertext);
        return 1;
    }

    printf("  PASS\n");
    return 0;
}

/* Test encryption secret vectors */
static int test_encryption_secret(void) {
    printf("Testing encryption secret vectors...\n");

    /* Test case 1: Single public key */
    const char *key1_hex = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279"
                           "a87bb0d480c8443";
    const char *expected_secret_hex = "752a7552d8aea88ad52cd65ba4d2c1e250cf9f10"
                                      "b12899d9b6253bf391f18190";
    const char *expected_individual_hex = "52e3b41f1e01c7ed4eb3464cb36bd4015380"
                                          "02b20402876e3e7e5be720ae1890";

    beb_pubkey_t key1;
    uint8_t expected_secret[32];
    uint8_t expected_individual[32];

    if (hex_decode(key1_hex, key1.data, sizeof(key1.data)) != 33) {
        printf("  FAIL: Invalid key\n");
        return 1;
    }
    hex_decode(expected_secret_hex, expected_secret, sizeof(expected_secret));
    hex_decode(expected_individual_hex, expected_individual,
               sizeof(expected_individual));

    uint8_t secret[32];
    beb_ll_error_t err = beb_ll_decryption_secret(&key1, 1, secret);
    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: decryption_secret failed: %s\n",
               beb_ll_error_string(err));
        return 1;
    }

    if (!bytes_equal(secret, 32, expected_secret, 32)) {
        printf("  FAIL: Decryption secret mismatch\n");
        return 1;
    }

    uint8_t individual[32];
    err = beb_ll_individual_secret(secret, &key1, individual);
    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: individual_secret failed: %s\n",
               beb_ll_error_string(err));
        return 1;
    }

    if (!bytes_equal(individual, 32, expected_individual, 32)) {
        printf("  FAIL: Individual secret mismatch\n");
        return 1;
    }

    printf("  PASS\n");
    return 0;
}

/* Test encrypted backup vectors */
static int test_encrypted_backup(void) {
    printf("Testing encrypted backup vectors...\n");

    /* Test case 1: Single key, no derivation paths, no content metadata */
    const char *key1_hex = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279"
                           "a87bb0d480c8443";
    const char *plaintext_hex = "00";
    const char *nonce_hex = "a1b2c3d4e5f607080910a1b2";
    const char *expected_hex = "42454201000152e3b41f1e01c7ed4eb3464cb36bd401538"
                               "002b20402876e3e7e5be720ae"
                               "189001a1b2c3d4e5f607080910a1b213a208315d1be8d22"
                               "c436e1d994d13a568cca38e";

    beb_pubkey_t key1;
    uint8_t nonce[12];
    uint8_t plaintext[16];
    uint8_t expected[256];

    if (hex_decode(key1_hex, key1.data, sizeof(key1.data)) != 33) {
        printf("  FAIL: Invalid key\n");
        return 1;
    }
    hex_decode(nonce_hex, nonce, sizeof(nonce));

    /* Note: In the Rust test code, plaintext from JSON is treated as a UTF-8
     * string */
    /* So "00" string becomes [0x30, 0x30] = 2 bytes, not hex-decoded [0x00] = 1
     * byte */
    /* This matches: plaintext.as_bytes() in Rust gives UTF-8 bytes of the
     * string
     */
    plaintext[0] = 0x30; /* '0' */
    plaintext[1] = 0x30; /* '0' */
    size_t plaintext_len = 2;
    size_t expected_len = hex_decode(expected_hex, expected, sizeof(expected));

    /* Create content metadata for None */
    beb_content_t content;
    content.type = BEB_CONTENT_NONE;

    /* Encrypt */
    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;
    beb_derivation_path_t *paths = NULL;
    size_t paths_count = 0;

    beb_ll_error_t err = beb_ll_encrypt_aes_gcm_256_v1_with_nonce(
        paths, paths_count, &content, &key1, 1, plaintext, plaintext_len, nonce,
        &encrypted, &encrypted_len);

    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: Encryption failed: %s\n", beb_ll_error_string(err));
        return 1;
    }

    if (!bytes_equal(encrypted, encrypted_len, expected, expected_len)) {
        printf("  FAIL: Encrypted output mismatch\n");
        printf("    Got length: %zu, Expected length: %zu\n", encrypted_len,
               expected_len);

        /* Find first difference */
        size_t diff_pos = 0;
        size_t min_len = encrypted_len < expected_len ? encrypted_len
                                                      : expected_len;
        for (size_t i = 0; i < min_len; i++) {
            if (encrypted[i] != expected[i]) {
                diff_pos = i;
                break;
            }
        }
        printf("    First difference at byte %zu\n", diff_pos);

        char got_hex[512];
        char exp_hex[512];
        hex_encode(encrypted, encrypted_len < 256 ? encrypted_len : 256,
                   got_hex);
        hex_encode(expected, expected_len < 256 ? expected_len : 256, exp_hex);
        printf("    Got:      %s\n", got_hex);
        printf("    Expected: %s\n", exp_hex);

        /* Show bytes around difference */
        printf("    Context around byte %zu:\n", diff_pos);
        printf("      Got:      ");
        for (size_t i = (diff_pos > 5 ? diff_pos - 5 : 0);
             i < diff_pos + 5 && i < encrypted_len; i++) {
            printf("%02x ", encrypted[i]);
        }
        printf("\n      Expected: ");
        for (size_t i = (diff_pos > 5 ? diff_pos - 5 : 0);
             i < diff_pos + 5 && i < expected_len; i++) {
            printf("%02x ", expected[i]);
        }
        printf("\n");

        free(encrypted);
        return 1;
    }

    /* Decode and decrypt */
    beb_decode_v1_result_t decode_result;
    err = beb_ll_decode_v1(encrypted, encrypted_len, &decode_result);
    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: Decode failed: %s\n", beb_ll_error_string(err));
        free(encrypted);
        return 1;
    }

    beb_decrypt_result_t decrypt_result;
    err = beb_ll_decrypt_aes_gcm_256_v1(
        &key1, decode_result.individual_secrets, decode_result.secrets_count,
        decode_result.cyphertext, decode_result.cyphertext_len,
        decode_result.nonce, &decrypt_result);

    if (err != BEB_LL_ERROR_OK) {
        printf("  FAIL: Decryption failed: %s\n", beb_ll_error_string(err));
        beb_ll_decode_v1_result_free(&decode_result);
        free(encrypted);
        return 1;
    }

    if (!bytes_equal(decrypt_result.data, decrypt_result.len, plaintext,
                     plaintext_len)) {
        printf("  FAIL: Decrypted plaintext mismatch\n");
        beb_ll_decrypt_result_free(&decrypt_result);
        beb_ll_decode_v1_result_free(&decode_result);
        free(encrypted);
        return 1;
    }

    beb_ll_decrypt_result_free(&decrypt_result);
    beb_ll_decode_v1_result_free(&decode_result);
    free(encrypted);

    printf("  PASS\n");
    return 0;
}

int main(void) {
    printf("BEB LL Test Vectors\n");
    printf("===================\n\n");

    int failures = 0;

    failures += test_aesgcm256_encryption();
    failures += test_encryption_secret();
    failures += test_encrypted_backup();

    printf("\n");
    if (failures == 0) {
        printf("All test vectors PASSED\n");
        return 0;
    } else {
        printf("%d test vector suite(s) FAILED\n", failures);
        return 1;
    }
}
