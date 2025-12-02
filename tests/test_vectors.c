#include "../include/beb.h"
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

/* Simple hex decode */
static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) {
        return 0;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[(i * 2) + 1];
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
        out[(i * 2) + 1] = hex_chars[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* Forward declarations for JSON vector helper types */
typedef struct content_type_vector_t content_type_vector_t;
typedef struct derivation_path_vector_t derivation_path_vector_t;
typedef struct individual_secrets_vector_t individual_secrets_vector_t;

struct content_type_vector_t {
    char *description;
    bool valid;
    uint8_t *content;
    size_t content_len;
};

struct derivation_path_vector_t {
    char *description;
    char **paths;
    size_t paths_count;
    uint8_t *expected;
    size_t expected_len;
    bool expect_success;
};

struct individual_secrets_vector_t {
    char *description;
    uint8_t *secrets;
    size_t secrets_count;
    uint8_t *expected;
    size_t expected_len;
    bool expect_success;
};

/* Prototypes for helpers used before their definitions */
static void free_content_type_vectors(content_type_vector_t *vecs,
                                      size_t count);
static void free_derivation_path_vectors(derivation_path_vector_t *vecs,
                                         size_t count);
static void free_individual_secrets_vectors(individual_secrets_vector_t *vecs,
                                            size_t count);

/* Compare byte arrays */
static bool
bytes_equal(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    if (a_len != b_len)
        return false;
    return memcmp(a, b, a_len) == 0;
}

static int compare_bytes32(const void *a, const void *b) {
    return memcmp(a, b, 32);
}

static size_t sort_and_unique_bytes32(uint8_t *data, size_t count) {
    if (count == 0)
        return 0;

    qsort(data, count, 32, compare_bytes32);

    size_t unique_count = 1;
    for (size_t i = 1; i < count; i++) {
        uint8_t *current = data + (i * 32);
        uint8_t *last_unique = data + ((unique_count - 1) * 32);
        if (memcmp(current, last_unique, 32) != 0) {
            if (unique_count != i) {
                memcpy(data + (unique_count * 32), current, 32);
            }
            unique_count++;
        }
    }

    return unique_count;
}

typedef struct {
    char *description;
    uint8_t nonce[12];
    size_t nonce_len;
    uint8_t *plaintext;
    size_t plaintext_len;
    uint8_t secret[32];
    size_t secret_len;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    bool expect_success; /* false when ciphertext is null in JSON */
} aesgcm_vector_t;

static void free_aesgcm_vectors(aesgcm_vector_t *vecs, size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        free(vecs[i].plaintext);
        free(vecs[i].ciphertext);
    }
    free(vecs);
}

static int load_content_type_vectors(const char *path,
                                     content_type_vector_t **out_vecs,
                                     size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    content_type_vector_t *vecs = (content_type_vector_t *)calloc(
        count, sizeof(content_type_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *valid = cJSON_GetObjectItem(item, "valid");
        cJSON *content = cJSON_GetObjectItem(item, "content");

        if (!cJSON_IsString(desc) || !cJSON_IsBool(valid) ||
            !cJSON_IsString(content)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }
        vecs[i].valid = cJSON_IsTrue(valid);

        size_t hex_len = strlen(content->valuestring);
        vecs[i].content = (uint8_t *)malloc((hex_len / 2) + 1); /* +1 safety */
        if (!vecs[i].content) {
            ok = false;
            break;
        }
        vecs[i].content_len = hex_decode(content->valuestring, vecs[i].content,
                                         (hex_len / 2) + 1);
        if (vecs[i].content_len == 0 && hex_len != 0) {
            ok = false;
            break;
        }
    }

    cJSON_Delete(root);
    if (!ok) {
        free_content_type_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int load_derivation_path_vectors(const char *path,
                                        derivation_path_vector_t **out_vecs,
                                        size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    derivation_path_vector_t *vecs = (derivation_path_vector_t *)calloc(
        count, sizeof(derivation_path_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *paths = cJSON_GetObjectItem(item, "paths");
        cJSON *expected = cJSON_GetObjectItem(item, "expected");

        if (!cJSON_IsString(desc) || !cJSON_IsArray(paths)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }

        size_t pcount = (size_t)cJSON_GetArraySize(paths);
        vecs[i].paths = (char **)calloc(pcount > 0 ? pcount : 1,
                                        sizeof(char *));
        if (!vecs[i].paths && pcount > 0) {
            ok = false;
            break;
        }
        vecs[i].paths_count = pcount;
        for (size_t j = 0; j < pcount; j++) {
            cJSON *p = cJSON_GetArrayItem(paths, (int)j);
            if (!cJSON_IsString(p)) {
                ok = false;
                break;
            }
            vecs[i].paths[j] = strdup(p->valuestring);
            if (!vecs[i].paths[j]) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;

        if (cJSON_IsNull(expected)) {
            vecs[i].expected = NULL;
            vecs[i].expected_len = 0;
            vecs[i].expect_success = false;
        } else if (cJSON_IsString(expected)) {
            size_t hex_len = strlen(expected->valuestring);
            vecs[i].expected = (uint8_t *)malloc((hex_len / 2) +
                                                 1); /* +1 safety */
            if (!vecs[i].expected) {
                ok = false;
                break;
            }
            vecs[i].expected_len = hex_decode(
                expected->valuestring, vecs[i].expected, (hex_len / 2) + 1);
            vecs[i].expect_success = true;
        } else {
            ok = false;
            break;
        }
    }

    cJSON_Delete(root);
    if (!ok) {
        free_derivation_path_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

static int
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
load_individual_secrets_vectors(const char *path,
                                individual_secrets_vector_t **out_vecs,
                                size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    individual_secrets_vector_t *vecs = (individual_secrets_vector_t *)calloc(
        count, sizeof(individual_secrets_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *secrets = cJSON_GetObjectItem(item, "secrets");
        cJSON *expected = cJSON_GetObjectItem(item, "expected");

        if (!cJSON_IsString(desc) || !cJSON_IsArray(secrets)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }

        size_t scount = (size_t)cJSON_GetArraySize(secrets);
        vecs[i].secrets = (uint8_t *)malloc(scount > 0 ? scount * 32 : 1);
        if (!vecs[i].secrets && scount > 0) {
            ok = false;
            break;
        }
        vecs[i].secrets_count = scount;

        for (size_t j = 0; j < scount; j++) {
            cJSON *s = cJSON_GetArrayItem(secrets, (int)j);
            if (!cJSON_IsString(s)) {
                ok = false;
                break;
            }
            if (hex_decode(s->valuestring, vecs[i].secrets + (j * 32), 32) !=
                32) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;

        if (cJSON_IsNull(expected)) {
            vecs[i].expected = NULL;
            vecs[i].expected_len = 0;
            vecs[i].expect_success = false;
        } else if (cJSON_IsString(expected)) {
            size_t hex_len = strlen(expected->valuestring);
            vecs[i].expected = (uint8_t *)malloc((hex_len / 2) + 1);
            if (!vecs[i].expected) {
                ok = false;
                break;
            }
            vecs[i].expected_len = hex_decode(
                expected->valuestring, vecs[i].expected, (hex_len / 2) + 1);
            vecs[i].expect_success = true;
        } else {
            ok = false;
            break;
        }
    }

    cJSON_Delete(root);
    if (!ok) {
        free_individual_secrets_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

static void free_content_type_vectors(content_type_vector_t *vecs,
                                      size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        free(vecs[i].content);
    }
    free(vecs);
}

static void free_derivation_path_vectors(derivation_path_vector_t *vecs,
                                         size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        if (vecs[i].paths) {
            for (size_t j = 0; j < vecs[i].paths_count; j++) {
                free(vecs[i].paths[j]);
            }
            free(vecs[i].paths);
        }
        free(vecs[i].expected);
    }
    free(vecs);
}

static void free_individual_secrets_vectors(individual_secrets_vector_t *vecs,
                                            size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        free(vecs[i].secrets);
        free(vecs[i].expected);
    }
    free(vecs);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int load_aesgcm_vectors(const char *path,
                               aesgcm_vector_t **out_vecs,
                               size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    aesgcm_vector_t *vecs = (aesgcm_vector_t *)calloc(count,
                                                      sizeof(aesgcm_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *nonce = cJSON_GetObjectItem(item, "nonce");
        cJSON *plaintext = cJSON_GetObjectItem(item, "plaintext");
        cJSON *secret = cJSON_GetObjectItem(item, "secret");
        cJSON *ciphertext = cJSON_GetObjectItem(item, "ciphertext");

        if (!cJSON_IsString(desc) || !cJSON_IsString(nonce) ||
            !cJSON_IsString(plaintext) || !cJSON_IsString(secret)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }

        vecs[i].nonce_len = hex_decode(nonce->valuestring, vecs[i].nonce,
                                       sizeof(vecs[i].nonce));

        size_t pt_hex_len = strlen(plaintext->valuestring);
        vecs[i].plaintext = (uint8_t *)malloc((pt_hex_len / 2) + 1);
        if (!vecs[i].plaintext) {
            ok = false;
            break;
        }
        vecs[i].plaintext_len = hex_decode(
            plaintext->valuestring, vecs[i].plaintext, (pt_hex_len / 2) + 1);

        vecs[i].secret_len = hex_decode(secret->valuestring, vecs[i].secret,
                                        sizeof(vecs[i].secret));

        if (cJSON_IsNull(ciphertext)) {
            vecs[i].expect_success = false;
            vecs[i].ciphertext = NULL;
            vecs[i].ciphertext_len = 0;
        } else if (cJSON_IsString(ciphertext)) {
            size_t ct_hex_len = strlen(ciphertext->valuestring);
            vecs[i].ciphertext = (uint8_t *)malloc((ct_hex_len / 2) + 1);
            if (!vecs[i].ciphertext) {
                ok = false;
                break;
            }
            vecs[i].ciphertext_len = hex_decode(ciphertext->valuestring,
                                                vecs[i].ciphertext,
                                                (ct_hex_len / 2) + 1);
            vecs[i].expect_success = true;
        } else {
            ok = false;
            break;
        }

        if (vecs[i].nonce_len != 12 || vecs[i].secret_len != 32) {
            ok = false;
            break;
        }
    }

    cJSON_Delete(root);

    if (!ok) {
        free_aesgcm_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_aesgcm256_encryption_json(void) {
    printf("Testing AES-GCM-256 encryption vectors from JSON... ");

    aesgcm_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_aesgcm_vectors("test_vectors/aesgcm256_encryption.json", &vecs,
                            &count) != 0) {
        printf("  FAIL: could not load AES-GCM JSON vectors\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        aesgcm_vector_t *v = &vecs[i];

        uint8_t *ciphertext = NULL;
        size_t ciphertext_len = 0;
        beb_error_t err = beb_encrypt_with_nonce(v->secret, v->plaintext,
                                                 v->plaintext_len, v->nonce,
                                                 &ciphertext, &ciphertext_len);

        if (!v->expect_success) {
            if (err == BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf(
                    "    FAIL: expected encryption failure but got success\n");
                free(ciphertext);
                failures++;
            }
            continue;
        }

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Encryption failed: %s\n", beb_error_string(err));
            failures++;
            continue;
        }

        if (!bytes_equal(ciphertext, ciphertext_len, v->ciphertext,
                         v->ciphertext_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Ciphertext mismatch\n");
            char got_hex[512];
            char exp_hex[512];
            size_t n = ciphertext_len < sizeof(got_hex) / 2
                           ? ciphertext_len
                           : (sizeof(got_hex) / 2) - 1;
            hex_encode(ciphertext, n, got_hex);
            n = v->ciphertext_len < sizeof(exp_hex) / 2
                    ? v->ciphertext_len
                    : (sizeof(exp_hex) / 2) - 1;
            hex_encode(v->ciphertext, n, exp_hex);
            printf("      Got:      %s\n", got_hex);
            printf("      Expected: %s\n", exp_hex);
            free(ciphertext);
            failures++;
            continue;
        }

        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;
        err = beb_try_decrypt_aes_gcm_256(ciphertext, ciphertext_len, v->secret,
                                          v->nonce, &decrypted, &decrypted_len);

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decryption failed: %s\n", beb_error_string(err));
            free(ciphertext);
            failures++;
            continue;
        }

        if (!bytes_equal(decrypted, decrypted_len, v->plaintext,
                         v->plaintext_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decrypted plaintext mismatch\n");
            free(ciphertext);
            free(decrypted);
            failures++;
            continue;
        }

        free(ciphertext);
        free(decrypted);
    }

    free_aesgcm_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

typedef struct {
    char *description;
    size_t keys_count;
    beb_pubkey_t *keys;
    uint8_t decryption_secret[32];
    uint8_t *individual_secrets;
    size_t individual_secrets_count;
} enc_secret_vector_t;

static void free_encryption_secret_vectors(enc_secret_vector_t *vecs,
                                           size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        free(vecs[i].keys);
        free(vecs[i].individual_secrets);
    }
    free(vecs);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int load_encryption_secret_vectors(const char *path,
                                          enc_secret_vector_t **out_vecs,
                                          size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    enc_secret_vector_t *vecs = (enc_secret_vector_t *)calloc(
        count, sizeof(enc_secret_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *keys = cJSON_GetObjectItem(item, "keys");
        cJSON *dec_sec = cJSON_GetObjectItem(item, "decryption_secret");
        cJSON *ind_secs = cJSON_GetObjectItem(item, "individual_secrets");

        if (!cJSON_IsString(desc) || !cJSON_IsArray(keys) ||
            !cJSON_IsString(dec_sec) || !cJSON_IsArray(ind_secs)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }

        size_t key_count = (size_t)cJSON_GetArraySize(keys);
        vecs[i].keys = (beb_pubkey_t *)calloc(key_count, sizeof(beb_pubkey_t));
        if (!vecs[i].keys) {
            ok = false;
            break;
        }
        vecs[i].keys_count = key_count;

        for (size_t k = 0; k < key_count; k++) {
            cJSON *kstr = cJSON_GetArrayItem(keys, (int)k);
            if (!cJSON_IsString(kstr)) {
                ok = false;
                break;
            }
            if (hex_decode(kstr->valuestring, vecs[i].keys[k].data,
                           sizeof(vecs[i].keys[k].data)) != 33) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;

        if (hex_decode(dec_sec->valuestring, vecs[i].decryption_secret,
                       sizeof(vecs[i].decryption_secret)) != 32) {
            ok = false;
            break;
        }

        size_t ind_count = (size_t)cJSON_GetArraySize(ind_secs);
        vecs[i].individual_secrets = (uint8_t *)calloc(ind_count,
                                                       32 * sizeof(uint8_t));
        if (!vecs[i].individual_secrets) {
            ok = false;
            break;
        }
        vecs[i].individual_secrets_count = ind_count;

        for (size_t j = 0; j < ind_count; j++) {
            cJSON *istr = cJSON_GetArrayItem(ind_secs, (int)j);
            if (!cJSON_IsString(istr)) {
                ok = false;
                break;
            }
            if (hex_decode(istr->valuestring,
                           vecs[i].individual_secrets + (j * 32), 32) != 32) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;
    }

    cJSON_Delete(root);
    if (!ok) {
        free_encryption_secret_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_encryption_secret_json(void) {
    printf("Testing encryption secret vectors from JSON... ");

    enc_secret_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_encryption_secret_vectors("test_vectors/encryption_secret.json",
                                       &vecs, &count) != 0) {
        printf("  FAIL: could not load encryption_secret JSON vectors\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        enc_secret_vector_t *v = &vecs[i];

        uint8_t secret[32];
        beb_error_t err = beb_decryption_secret(v->keys, v->keys_count, secret);
        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: decryption_secret failed: %s\n",
                   beb_error_string(err));
            failures++;
            continue;
        }

        if (!bytes_equal(secret, 32, v->decryption_secret, 32)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decryption secret mismatch\n");
            failures++;
            continue;
        }

        uint8_t *computed = NULL;
        uint8_t *expected = NULL;

        if (v->keys_count > 0) {
            computed = (uint8_t *)malloc(v->keys_count * 32);
        }
        if (v->individual_secrets_count > 0) {
            expected = (uint8_t *)malloc(v->individual_secrets_count * 32);
        }
        if ((v->keys_count > 0 && !computed) ||
            (v->individual_secrets_count > 0 && !expected)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Memory allocation failed\n");
            free(computed);
            free(expected);
            failures++;
            continue;
        }

        size_t computed_count = 0;
        bool indiv_err = false;
        for (size_t j = 0; j < v->keys_count; j++) {
            beb_error_t indiv = beb_individual_secret(
                secret, &v->keys[j], computed + (computed_count * 32));
            if (indiv != BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf("    FAIL: individual_secret failed: %s\n",
                       beb_error_string(indiv));
                failures++;
                indiv_err = true;
                break;
            }
            computed_count++;
        }

        if (indiv_err) {
            free(computed);
            free(expected);
            continue;
        }

        memcpy(expected, v->individual_secrets,
               v->individual_secrets_count * 32);

        size_t computed_unique = sort_and_unique_bytes32(computed,
                                                         computed_count);
        size_t expected_unique = sort_and_unique_bytes32(
            expected, v->individual_secrets_count);

        if (computed_unique != expected_unique ||
            memcmp(computed, expected, expected_unique * 32) != 0) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Individual secret set mismatch\n");
            failures++;
        }

        free(computed);
        free(expected);
    }

    free_encryption_secret_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

typedef struct {
    char *description;
    uint8_t version;
    uint8_t encryption;
    uint8_t *content;
    size_t content_len;
    beb_pubkey_t *keys;
    size_t keys_count;
    char **derivation_paths;
    size_t derivation_paths_count;
    char *plaintext; /* UTF-8 bytes, not hex */
    size_t plaintext_len;
    uint8_t nonce[12];
    size_t nonce_len;
    uint8_t *expected;
    size_t expected_len;
} backup_vector_t;

static void free_backup_vectors(backup_vector_t *vecs, size_t count) {
    if (!vecs)
        return;
    for (size_t i = 0; i < count; i++) {
        free(vecs[i].description);
        free(vecs[i].content);
        free(vecs[i].keys);
        if (vecs[i].derivation_paths) {
            for (size_t j = 0; j < vecs[i].derivation_paths_count; j++) {
                free(vecs[i].derivation_paths[j]);
            }
            free(vecs[i].derivation_paths);
        }
        free(vecs[i].plaintext);
        free(vecs[i].expected);
    }
    free(vecs);
}

/* Very small BIP32-style derivation path parser for tests.
 * Supports strings like "m/84'/0'/0'" or "m/0/1'/2/3'".
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int parse_derivation_path_string(const char *s,
                                        beb_derivation_path_t *out) {
    if (!s || !out)
        return 0;

    size_t len = strlen(s);
    if (len == 0 || s[0] != 'm')
        return 0;

    /* First pass: count segments */
    size_t count = 0;
    for (size_t i = 1; i < len; i++) {
        if (s[i] == '/')
            count++;
    }
    if (count == 0) {
        out->children = NULL;
        out->count = 0;
        return 1;
    }

    out->children = (uint32_t *)calloc(count, sizeof(uint32_t));
    if (!out->children) {
        out->count = 0;
        return 0;
    }
    out->count = count;

    /* Second pass: parse each segment */
    size_t seg_idx = 0;
    const char *p = s + 1; /* start after 'm' */
    while (*p && seg_idx < count) {
        if (*p != '/') {
            /* malformed */
            free(out->children);
            out->children = NULL;
            out->count = 0;
            return 0;
        }
        p++; /* skip '/' */

        const char *start = p;
        while (*p && *p != '/')
            p++;

        size_t seg_len = (size_t)(p - start);
        if (seg_len == 0) {
            free(out->children);
            out->children = NULL;
            out->count = 0;
            return 0;
        }

        bool hardened = false;
        if (start[seg_len - 1] == '\'') {
            hardened = true;
            seg_len--;
        }

        char buf[32];
        if (seg_len >= sizeof(buf)) {
            free(out->children);
            out->children = NULL;
            out->count = 0;
            return 0;
        }
        memcpy(buf, start, seg_len);
        buf[seg_len] = '\0';

        char *endptr = NULL;
        unsigned long idx = strtoul(buf, &endptr, 10);
        if (endptr == buf || *endptr != '\0' || idx > 0x7fffffffUL) {
            free(out->children);
            out->children = NULL;
            out->count = 0;
            return 0;
        }

        uint32_t val = (uint32_t)idx;
        if (hardened) {
            val |= 0x80000000UL;
        }
        out->children[seg_idx++] = val;
    }

    if (seg_idx != count) {
        free(out->children);
        out->children = NULL;
        out->count = 0;
        return 0;
    }

    return 1;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int load_encrypted_backup_vectors(const char *path,
                                         backup_vector_t **out_vecs,
                                         size_t *out_count) {
    *out_vecs = NULL;
    *out_count = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return 1;
    }
    buf[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Invalid JSON in %s\n", path);
        cJSON_Delete(root);
        return 1;
    }

    size_t count = (size_t)cJSON_GetArraySize(root);
    backup_vector_t *vecs = (backup_vector_t *)calloc(count,
                                                      sizeof(backup_vector_t));
    if (!vecs) {
        cJSON_Delete(root);
        return 1;
    }

    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        cJSON *item = cJSON_GetArrayItem(root, (int)i);
        if (!cJSON_IsObject(item)) {
            ok = false;
            break;
        }

        cJSON *desc = cJSON_GetObjectItem(item, "description");
        cJSON *version = cJSON_GetObjectItem(item, "version");
        cJSON *encryption = cJSON_GetObjectItem(item, "encryption");
        cJSON *content = cJSON_GetObjectItem(item, "content");
        cJSON *keys = cJSON_GetObjectItem(item, "keys");
        cJSON *derivation_paths = cJSON_GetObjectItem(item, "derivation_paths");
        cJSON *plaintext = cJSON_GetObjectItem(item, "plaintext");
        cJSON *nonce = cJSON_GetObjectItem(item, "nonce");
        cJSON *expected = cJSON_GetObjectItem(item, "expected");

        if (!cJSON_IsString(desc) || !cJSON_IsNumber(version) ||
            !cJSON_IsNumber(encryption) || !cJSON_IsString(content) ||
            !cJSON_IsArray(keys) || !cJSON_IsArray(derivation_paths) ||
            !cJSON_IsString(plaintext) || !cJSON_IsString(nonce) ||
            !cJSON_IsString(expected)) {
            ok = false;
            break;
        }

        vecs[i].description = strdup(desc->valuestring);
        if (!vecs[i].description) {
            ok = false;
            break;
        }
        vecs[i].version = (uint8_t)version->valuedouble;
        vecs[i].encryption = (uint8_t)encryption->valuedouble;

        size_t content_hex_len = strlen(content->valuestring);
        vecs[i].content = (uint8_t *)malloc((content_hex_len / 2) + 1);
        if (!vecs[i].content) {
            ok = false;
            break;
        }
        vecs[i].content_len = hex_decode(content->valuestring, vecs[i].content,
                                         (content_hex_len / 2) + 1);

        size_t key_count = (size_t)cJSON_GetArraySize(keys);
        vecs[i].keys = (beb_pubkey_t *)calloc(key_count, sizeof(beb_pubkey_t));
        if (!vecs[i].keys) {
            ok = false;
            break;
        }
        vecs[i].keys_count = key_count;
        for (size_t k = 0; k < key_count; k++) {
            cJSON *kstr = cJSON_GetArrayItem(keys, (int)k);
            if (!cJSON_IsString(kstr)) {
                ok = false;
                break;
            }
            if (hex_decode(kstr->valuestring, vecs[i].keys[k].data,
                           sizeof(vecs[i].keys[k].data)) != 33) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;

        size_t dp_count = (size_t)cJSON_GetArraySize(derivation_paths);
        vecs[i].derivation_paths = (char **)calloc(dp_count, sizeof(char *));
        if (!vecs[i].derivation_paths) {
            ok = false;
            break;
        }
        vecs[i].derivation_paths_count = dp_count;
        for (size_t d = 0; d < dp_count; d++) {
            cJSON *dp = cJSON_GetArrayItem(derivation_paths, (int)d);
            if (!cJSON_IsString(dp)) {
                ok = false;
                break;
            }
            vecs[i].derivation_paths[d] = strdup(dp->valuestring);
            if (!vecs[i].derivation_paths[d]) {
                ok = false;
                break;
            }
        }
        if (!ok)
            break;

        vecs[i].plaintext_len = strlen(plaintext->valuestring);
        vecs[i].plaintext = (char *)malloc(vecs[i].plaintext_len);
        if (!vecs[i].plaintext) {
            ok = false;
            break;
        }
        memcpy(vecs[i].plaintext, plaintext->valuestring,
               vecs[i].plaintext_len);

        vecs[i].nonce_len = hex_decode(nonce->valuestring, vecs[i].nonce,
                                       sizeof(vecs[i].nonce));

        size_t expected_hex_len = strlen(expected->valuestring);
        vecs[i].expected = (uint8_t *)malloc((expected_hex_len / 2) + 1);
        if (!vecs[i].expected) {
            ok = false;
            break;
        }
        vecs[i].expected_len = hex_decode(expected->valuestring,
                                          vecs[i].expected,
                                          (expected_hex_len / 2) + 1);
    }

    cJSON_Delete(root);
    if (!ok) {
        free_backup_vectors(vecs, count);
        return 1;
    }

    *out_vecs = vecs;
    *out_count = count;
    return 0;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_encrypted_backup_json(void) {
    printf("Testing encrypted backup vectors from JSON... ");

    backup_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_encrypted_backup_vectors("test_vectors/encrypted_backup.json",
                                      &vecs, &count) != 0) {
        printf("  FAIL: could not load encrypted_backup JSON vectors\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        backup_vector_t *v = &vecs[i];

        beb_derivation_path_t *paths = NULL;
        size_t paths_count = v->derivation_paths_count;
        if (paths_count > 0) {
            paths = (beb_derivation_path_t *)calloc(
                paths_count, sizeof(beb_derivation_path_t));
            if (!paths) {
                failures++;
                break;
            }
            for (size_t d = 0; d < paths_count; d++) {
                if (!parse_derivation_path_string(v->derivation_paths[d],
                                                  &paths[d])) {
                    printf("  Case %zu: %s\n", i + 1,
                           v->description ? v->description
                                          : "(no description)");
                    printf("    FAIL: Could not parse derivation path \"%s\"\n",
                           v->derivation_paths[d]);
                    for (size_t j = 0; j <= d; j++) {
                        free(paths[j].children);
                    }
                    free(paths);
                    paths = NULL;
                    failures++;
                    goto next_case;
                }
            }
        }

        beb_content_t content;
        size_t content_offset = 0;
        beb_error_t err = beb_parse_content_metadata(v->content, v->content_len,
                                                     &content_offset, &content);
        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Content parse failed: %s\n",
                   beb_error_string(err));
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            failures++;
            continue;
        }

        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;
        err = beb_encrypt_aes_gcm_256_v1_with_nonce(
            paths, paths_count, &content, v->keys, v->keys_count,
            (const uint8_t *)v->plaintext, v->plaintext_len, v->nonce,
            &encrypted, &encrypted_len);

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Encryption failed: %s\n", beb_error_string(err));
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            failures++;
            continue;
        }

        if (!bytes_equal(encrypted, encrypted_len, v->expected,
                         v->expected_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Encrypted output mismatch\n");
            size_t sample_len = encrypted_len < 16 ? encrypted_len : (size_t)16;
            char got_hex[33];
            char exp_hex[33];
            hex_encode(encrypted, sample_len, got_hex);
            hex_encode(v->expected, sample_len, exp_hex);
            printf("      Got (first %zu bytes): %s\n", sample_len, got_hex);
            printf("      Exp (first %zu bytes): %s\n", sample_len, exp_hex);
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        beb_decode_v1_result_t decode_result;
        err = beb_decode_v1(encrypted, encrypted_len, &decode_result);
        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decode failed: %s\n", beb_error_string(err));
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        if (decode_result.secrets_count == 0) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: No individual secrets in decoded backup\n");
            beb_decode_v1_result_free(&decode_result);
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        SHA256_CTX ctx;
        uint8_t si[32];
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, BEB_INDIVIDUAL_SECRET,
                      strlen(BEB_INDIVIDUAL_SECRET));
        SHA256_Update(&ctx, v->keys[0].data, sizeof(v->keys[0].data));
        SHA256_Final(si, &ctx);

        uint8_t secret[32];
        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;
        bool decrypted_ok = false;
        beb_error_t decrypt_err = BEB_ERROR_DECRYPT;

        for (size_t s = 0; s < decode_result.secrets_count; s++) {
            beb_error_t xor_err = beb_xor(
                decode_result.individual_secrets[s].data, si, secret);
            if (xor_err != BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf("    FAIL: XOR failed: %s\n", beb_error_string(xor_err));
                beb_decode_v1_result_free(&decode_result);
                beb_content_free(&content);
                if (paths) {
                    for (size_t d = 0; d < paths_count; d++) {
                        free(paths[d].children);
                    }
                    free(paths);
                }
                free(encrypted);
                failures++;
                goto next_case;
            }

            uint8_t *candidate_plaintext = NULL;
            size_t candidate_len = 0;
            beb_error_t try_err = beb_try_decrypt_aes_gcm_256(
                decode_result.cyphertext, decode_result.cyphertext_len, secret,
                decode_result.nonce, &candidate_plaintext, &candidate_len);

            if (try_err == BEB_ERROR_OK) {
                decrypted = candidate_plaintext;
                decrypted_len = candidate_len;
                decrypted_ok = true;
                break;
            }

            decrypt_err = try_err;
        }

        if (!decrypted_ok) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decryption failed: %s\n",
                   beb_error_string(decrypt_err));
            beb_decode_v1_result_free(&decode_result);
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        beb_content_t decoded_content;
        size_t offset = 0;
        err = beb_parse_content_metadata(decrypted, decrypted_len, &offset,
                                         &decoded_content);
        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Content metadata parse failed: %s\n",
                   beb_error_string(err));
            beb_content_free(&decoded_content);
            free(decrypted);
            beb_decode_v1_result_free(&decode_result);
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        size_t decrypted_payload_len = decrypted_len - offset;
        if (!bytes_equal(decrypted + offset, decrypted_payload_len,
                         (const uint8_t *)v->plaintext, v->plaintext_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: Decrypted plaintext mismatch\n");
            beb_content_free(&decoded_content);
            free(decrypted);
            beb_decode_v1_result_free(&decode_result);
            beb_content_free(&content);
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            free(encrypted);
            failures++;
            continue;
        }

        beb_content_free(&decoded_content);
        free(decrypted);
        beb_decode_v1_result_free(&decode_result);
        beb_content_free(&content);
        if (paths) {
            for (size_t d = 0; d < paths_count; d++) {
                free(paths[d].children);
            }
            free(paths);
        }
        free(encrypted);

    next_case:;
    }

    free_backup_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_content_type_json(void) {
    printf("Testing content type vectors from JSON... ");

    content_type_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_content_type_vectors("test_vectors/content_type.json", &vecs,
                                  &count) != 0) {
        printf("FAILED (load)\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        content_type_vector_t *v = &vecs[i];

        beb_content_t content;
        size_t offset = 0;
        beb_error_t err = beb_parse_content_metadata(v->content, v->content_len,
                                                     &offset, &content);

        if (!v->valid) {
            if (err == BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf("    FAIL: expected parse failure but got success\n");
                beb_content_free(&content);
                failures++;
            }
            continue;
        }

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: parse failed: %s\n", beb_error_string(err));
            failures++;
            continue;
        }

        uint8_t *encoded = NULL;
        size_t encoded_len = 0;
        err = beb_encode_content(&content, &encoded, &encoded_len);
        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: encode failed: %s\n", beb_error_string(err));
            beb_content_free(&content);
            failures++;
            continue;
        }

        if (!bytes_equal(encoded, encoded_len, v->content, v->content_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: roundtrip mismatch\n");
            failures++;
        }

        free(encoded);
        beb_content_free(&content);
    }

    free_content_type_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_derivation_path_json(void) {
    printf("Testing derivation path vectors from JSON... ");

    derivation_path_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_derivation_path_vectors("test_vectors/derivation_path.json", &vecs,
                                     &count) != 0) {
        printf("FAILED (load)\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        derivation_path_vector_t *v = &vecs[i];

        beb_derivation_path_t *paths = NULL;
        size_t paths_count = v->paths_count;
        if (paths_count > 0) {
            paths = (beb_derivation_path_t *)calloc(
                paths_count, sizeof(beb_derivation_path_t));
            if (!paths) {
                failures++;
                break;
            }
            for (size_t d = 0; d < paths_count; d++) {
                if (!parse_derivation_path_string(v->paths[d], &paths[d])) {
                    printf("  Case %zu: %s\n", i + 1,
                           v->description ? v->description
                                          : "(no description)");
                    printf("    FAIL: Could not parse derivation path \"%s\"\n",
                           v->paths[d]);
                    for (size_t j = 0; j <= d; j++) {
                        free(paths[j].children);
                    }
                    free(paths);
                    paths = NULL;
                    failures++;
                    goto next_deriv_case;
                }
            }
        }

        uint8_t *encoded = NULL;
        size_t encoded_len = 0;
        beb_error_t err = beb_encode_derivation_paths(paths, paths_count,
                                                      &encoded, &encoded_len);

        if (!v->expect_success) {
            if (err == BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf("    FAIL: expected failure but got success\n");
                free(encoded);
                failures++;
            }
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            continue;
        }

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: encode failed: %s\n", beb_error_string(err));
            if (paths) {
                for (size_t d = 0; d < paths_count; d++) {
                    free(paths[d].children);
                }
                free(paths);
            }
            failures++;
            continue;
        }

        if (!bytes_equal(encoded, encoded_len, v->expected, v->expected_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: encoded bytes mismatch\n");
            failures++;
        }

        free(encoded);
        if (paths) {
            for (size_t d = 0; d < paths_count; d++) {
                free(paths[d].children);
            }
            free(paths);
        }

    next_deriv_case:;
    }

    free_derivation_path_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static int test_individual_secrets_json(void) {
    printf("Testing individual secrets vectors from JSON... ");

    individual_secrets_vector_t *vecs = NULL;
    size_t count = 0;
    if (load_individual_secrets_vectors("test_vectors/individual_secrets.json",
                                        &vecs, &count) != 0) {
        printf("FAILED (load)\n");
        return 1;
    }

    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        individual_secrets_vector_t *v = &vecs[i];

        beb_secret_t *secrets = NULL;
        if (v->secrets_count > 0) {
            secrets = (beb_secret_t *)calloc(v->secrets_count,
                                             sizeof(beb_secret_t));
            if (!secrets) {
                failures++;
                break;
            }
            for (size_t j = 0; j < v->secrets_count; j++) {
                memcpy(secrets[j].data, v->secrets + (j * 32), 32);
            }
        }

        uint8_t *encoded = NULL;
        size_t encoded_len = 0;
        beb_error_t err = beb_encode_individual_secrets(
            secrets, v->secrets_count, &encoded, &encoded_len);

        if (!v->expect_success) {
            if (err == BEB_ERROR_OK) {
                printf("  Case %zu: %s\n", i + 1,
                       v->description ? v->description : "(no description)");
                printf("    FAIL: expected failure but got success\n");
                free(encoded);
                failures++;
            }
            free(secrets);
            continue;
        }

        if (err != BEB_ERROR_OK) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: encode failed: %s\n", beb_error_string(err));
            free(secrets);
            failures++;
            continue;
        }

        if (!bytes_equal(encoded, encoded_len, v->expected, v->expected_len)) {
            printf("  Case %zu: %s\n", i + 1,
                   v->description ? v->description : "(no description)");
            printf("    FAIL: encoded bytes mismatch\n");
            failures++;
        }

        free(encoded);
        free(secrets);
    }

    free_individual_secrets_vectors(vecs, count);
    if (failures == 0) {
        printf("OK\n");
    } else {
        printf("FAILED\n");
    }
    return failures;
}

int main(void) {
    printf("BEB LL Test Vectors\n");
    printf("===================\n\n");

    int failures = 0;

    failures += test_aesgcm256_encryption_json();
    failures += test_encryption_secret_json();
    failures += test_encrypted_backup_json();
    failures += test_content_type_json();
    failures += test_derivation_path_json();
    failures += test_individual_secrets_json();

    printf("\n");
    if (failures == 0) {
        printf("All test vectors PASSED\n");
        return 0;
    }
    printf("%d test vector suite(s) FAILED\n", failures);
    return 1;
}
