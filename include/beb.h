#ifndef BEB_H
#define BEB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error types matching ll::Error */
typedef enum {
    BEB_ERROR_OK = 0,
    BEB_ERROR_KEY_COUNT,
    BEB_ERROR_DERIV_PATH_COUNT,
    BEB_ERROR_DERIV_PATH_LENGTH,
    BEB_ERROR_DERIV_PATH_EMPTY,
    BEB_ERROR_DATA_LENGTH,
    BEB_ERROR_ENCRYPT,
    BEB_ERROR_DECRYPT,
    BEB_ERROR_CORRUPTED,
    BEB_ERROR_VERSION,
    BEB_ERROR_MAGIC,
    BEB_ERROR_VARINT,
    BEB_ERROR_WRONG_KEY,
    BEB_ERROR_INDIVIDUAL_SECRETS_EMPTY,
    BEB_ERROR_INDIVIDUAL_SECRETS_LENGTH,
    BEB_ERROR_CYPHERTEXT_EMPTY,
    BEB_ERROR_CYPHERTEXT_LENGTH,
    BEB_ERROR_CONTENT_METADATA,
    BEB_ERROR_ENCRYPTION,
    BEB_ERROR_OFFSET_OVERFLOW,
    BEB_ERROR_EMPTY_BYTES,
    BEB_ERROR_INCREMENT,
    BEB_ERROR_CONTENT_METADATA_EMPTY,
    BEB_ERROR_CONTENT_RESERVED
} beb_error_t;

/* Content types matching ll::Content */
typedef enum {
    BEB_CONTENT_NONE,
    BEB_CONTENT_BIP380,
    BEB_CONTENT_BIP388,
    BEB_CONTENT_BIP329,
    BEB_CONTENT_BIP,         /* Generic BIP number (stored separately) */
    BEB_CONTENT_PROPRIETARY, /* Proprietary data (stored separately) */
    BEB_CONTENT_UNKNOWN
} beb_content_type_t;

/* Content structure for BIP and Proprietary types */
typedef struct {
    beb_content_type_t type;

    union {
        uint16_t bip_number; /* For BIP type */

        struct {
            uint8_t *data;
            size_t len;
        } proprietary; /* For Proprietary type */
    } u;
} beb_content_t;

/* Derivation path structure */
typedef struct {
    uint32_t *children;
    size_t count;
} beb_derivation_path_t;

/* Public key (33 bytes compressed) */
typedef struct {
    uint8_t data[33];
} beb_pubkey_t;

/* Individual secret (32 bytes) */
typedef struct {
    uint8_t data[32];
} beb_secret_t;

/* Result structure for decryption */
typedef struct {
    beb_content_t content;
    uint8_t *data;
    size_t len;
} beb_decrypt_result_t;

/* Result structure for decode_v1 */
typedef struct {
    beb_derivation_path_t *paths;
    size_t paths_count;
    beb_secret_t *individual_secrets;
    size_t secrets_count;
    uint8_t encryption_type;
    uint8_t nonce[12];
    uint8_t *cyphertext;
    size_t cyphertext_len;
} beb_decode_v1_result_t;

/* Constants */
#define BEB_MAGIC "BEB"
#define BEB_MAGIC_LEN 3
#define BEB_DECRYPTION_SECRET "BEB_BACKUP_DECRYPTION_SECRET"
#define BEB_INDIVIDUAL_SECRET "BEB_BACKUP_INDIVIDUAL_SECRET"
#define BEB_BIP341_NUMS_PUBKEY                                                 \
    "\x02\x50\x92\x9b\x74\xc1\xa0\x49\x54\xb7\x8b\x4b\x60\x35\xe9\x7a\x5e\x07" \
    "\x8a\x5a\x0f\x28\xec\x96\xd5\x47\xbf\xee\x9a\xce\x80\x3a\xc0"

/* Utility functions */
beb_error_t beb_xor(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);
const char *beb_error_string(beb_error_t error);

/* Offset checking utilities */
beb_error_t
beb_check_offset(size_t offset, const uint8_t *bytes, size_t bytes_len);
beb_error_t beb_check_offset_lookahead(size_t offset,
                                       const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t lookahead);
beb_error_t beb_init_offset(const uint8_t *bytes,
                            size_t bytes_len,
                            size_t value,
                            size_t *out);
beb_error_t beb_increment_offset(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t offset,
                                 size_t incr,
                                 size_t *out);

/* VarInt encoding/decoding (Bitcoin consensus format) */
size_t beb_varint_encode_size(uint64_t value);
beb_error_t beb_varint_encode(uint64_t value,
                              uint8_t *out,
                              size_t out_len,
                              size_t *written);
beb_error_t beb_varint_decode(const uint8_t *bytes,
                              size_t bytes_len,
                              size_t *offset,
                              uint64_t *value);

/* Content metadata functions */
beb_error_t beb_parse_content_metadata(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_content_t *content_out);
beb_error_t beb_encode_content(const beb_content_t *content,
                               uint8_t **out,
                               size_t *out_len);
void beb_content_free(beb_content_t *content);
bool beb_content_is_known(const beb_content_t *content);

/* Cryptographic functions */
beb_error_t beb_decryption_secret(const beb_pubkey_t *keys,
                                  size_t keys_count,
                                  uint8_t secret_out[32]);
beb_error_t beb_individual_secret(const uint8_t secret[32],
                                  const beb_pubkey_t *key,
                                  uint8_t individual_secret_out[32]);
beb_error_t beb_individual_secrets(const uint8_t secret[32],
                                   const beb_pubkey_t *keys,
                                   size_t keys_count,
                                   beb_secret_t **secrets_out,
                                   size_t *secrets_count_out);
beb_error_t beb_encrypt_with_nonce(const uint8_t secret[32],
                                   const uint8_t *data,
                                   size_t data_len,
                                   const uint8_t nonce[12],
                                   uint8_t **ciphertext_out,
                                   size_t *ciphertext_len_out);
beb_error_t beb_try_decrypt_aes_gcm_256(const uint8_t *ciphertext,
                                        size_t ciphertext_len,
                                        const uint8_t secret[32],
                                        const uint8_t nonce[12],
                                        uint8_t **plaintext_out,
                                        size_t *plaintext_len_out);

/* Encoding functions */
beb_error_t beb_encode_derivation_paths(const beb_derivation_path_t *paths,
                                        size_t paths_count,
                                        uint8_t **out,
                                        size_t *out_len);
beb_error_t beb_encode_individual_secrets(const beb_secret_t *secrets,
                                          size_t secrets_count,
                                          uint8_t **out,
                                          size_t *out_len);
beb_error_t beb_encode_encrypted_payload(const uint8_t nonce[12],
                                         const uint8_t *cyphertext,
                                         size_t cyphertext_len,
                                         uint8_t **out,
                                         size_t *out_len);
beb_error_t beb_encode_v1(uint8_t version,
                          const uint8_t *derivation_paths,
                          size_t deriv_paths_len,
                          const uint8_t *individual_secrets,
                          size_t individual_secrets_len,
                          uint8_t encryption,
                          const uint8_t *encrypted_payload,
                          size_t encrypted_payload_len,
                          uint8_t **out,
                          size_t *out_len);

/* Parsing functions */
beb_error_t beb_parse_magic_byte(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out);
beb_error_t beb_parse_version(const uint8_t *bytes,
                              size_t bytes_len,
                              size_t *offset_out,
                              uint8_t *version_out);
beb_error_t beb_parse_encryption(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out,
                                 uint8_t *encryption_out);
beb_error_t beb_parse_derivation_paths(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_derivation_path_t **paths_out,
                                       size_t *paths_count_out);
beb_error_t beb_parse_individual_secrets(const uint8_t *bytes,
                                         size_t bytes_len,
                                         size_t *offset_out,
                                         beb_secret_t **secrets_out,
                                         size_t *secrets_count_out);
beb_error_t beb_parse_encrypted_payload(const uint8_t *bytes,
                                        size_t bytes_len,
                                        size_t *offset_out,
                                        uint8_t nonce_out[12],
                                        uint8_t **cyphertext_out,
                                        size_t *cyphertext_len_out);
beb_error_t beb_decode_version(const uint8_t *bytes,
                               size_t bytes_len,
                               uint8_t *version_out);
beb_error_t beb_decode_derivation_paths(const uint8_t *bytes,
                                        size_t bytes_len,
                                        beb_derivation_path_t **paths_out,
                                        size_t *paths_count_out);
beb_error_t beb_decode_v1(const uint8_t *bytes,
                          size_t bytes_len,
                          beb_decode_v1_result_t *result_out);

/* High-level operations */
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
    size_t *out_len);

/* Memory management */
void beb_derivation_paths_free(beb_derivation_path_t *paths, size_t count);
void beb_secrets_free(beb_secret_t *secrets, size_t count);
void beb_decode_v1_result_free(beb_decode_v1_result_t *result);
void beb_decrypt_result_free(beb_decrypt_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BEB_H */
