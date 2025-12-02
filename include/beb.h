#ifndef BEB_H
#define BEB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/* High-level content categories for encoded backups. */
typedef enum {
    BEB_CONTENT_NONE,
    BEB_CONTENT_BIP380,
    BEB_CONTENT_BIP388,
    BEB_CONTENT_BIP329,
    BEB_CONTENT_BIP,         /* Generic BIP number (stored separately) */
    BEB_CONTENT_PROPRIETARY, /* Proprietary data (stored separately) */
    BEB_CONTENT_UNKNOWN
} beb_content_type_t;

/* Describes the backup content metadata, including BIP numbers and proprietary payloads. */
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

/* Represents a BIP32-style derivation path as a list of child indices. */
typedef struct {
    uint32_t *children;
    size_t count;
} beb_derivation_path_t;

/* Compressed secp256k1 public key (33-byte serialized form). */
typedef struct {
    uint8_t data[33];
} beb_pubkey_t;

/* Per-recipient 32-byte secret derived from the shared decryption secret. */
typedef struct {
    uint8_t data[32];
} beb_secret_t;

/* Result of a decryption operation, including parsed content metadata and plaintext bytes. */
typedef struct {
    beb_content_t content;
    uint8_t *data;
    size_t len;
} beb_decrypt_result_t;

/* Parsed components of a BEB v1-encoded backup blob. */
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

/* String constants used for BEB v1 encoding and key derivation. */
#define BEB_MAGIC "BEB"
#define BEB_MAGIC_LEN 3
#define BEB_DECRYPTION_SECRET "BEB_BACKUP_DECRYPTION_SECRET"
#define BEB_INDIVIDUAL_SECRET "BEB_BACKUP_INDIVIDUAL_SECRET"
#define BEB_BIP341_NUMS_PUBKEY                                                 \
    "\x02\x50\x92\x9b\x74\xc1\xa0\x49\x54\xb7\x8b\x4b\x60\x35\xe9\x7a\x5e\x07" \
    "\x8a\x5a\x0f\x28\xec\x96\xd5\x47\xbf\xee\x9a\xce\x80\x3a\xc0"

beb_error_t beb_xor(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

const char *beb_error_string(beb_error_t error);

/* Verify that offset refers to a valid position within the byte buffer. */
beb_error_t
beb_check_offset(size_t offset, const uint8_t *bytes, size_t bytes_len);
/* Verify that [offset, offset + lookahead) fully lies within the byte buffer. */
beb_error_t beb_check_offset_lookahead(size_t offset,
                                       const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t lookahead);
/* Initialize a checked offset value inside the given byte buffer. */
beb_error_t beb_init_offset(const uint8_t *bytes,
                            size_t bytes_len,
                            size_t value,
                            size_t *out);
/* Safely advance an offset by incr within the given byte buffer. */
beb_error_t beb_increment_offset(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t offset,
                                 size_t incr,
                                 size_t *out);

/* Return the number of bytes required to encode a Bitcoin-style VarInt. */
size_t beb_varint_encode_size(uint64_t value);
/* Encode a Bitcoin-style VarInt value into out and report bytes written. */
beb_error_t beb_varint_encode(uint64_t value,
                              uint8_t *out,
                              size_t out_len,
                              size_t *written);
/* Decode a Bitcoin-style VarInt from bytes, updating offset and value. */
beb_error_t beb_varint_decode(const uint8_t *bytes,
                              size_t bytes_len,
                              size_t *offset,
                              uint64_t *value);

/* Parse backup content metadata from bytes into a beb_content_t structure. */
beb_error_t beb_parse_content_metadata(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_content_t *content_out);
/* Encode a beb_content_t description into a newly allocated byte buffer. */
beb_error_t beb_encode_content(const beb_content_t *content,
                               uint8_t **out,
                               size_t *out_len);

void beb_content_free(beb_content_t *content);

/* Return true if the content type represents a known BIP-defined kind. */
bool beb_content_is_known(const beb_content_t *content);

/* Derive the shared 32-byte decryption secret from a set of recipient keys. */
beb_error_t beb_decryption_secret(const beb_pubkey_t *keys,
                                  size_t keys_count,
                                  uint8_t secret_out[32]);
/* Derive a per-recipient 32-byte secret from the shared secret and a pubkey. */
beb_error_t beb_individual_secret(const uint8_t secret[32],
                                  const beb_pubkey_t *key,
                                  uint8_t individual_secret_out[32]);
/* Derive per-recipient secrets for all provided keys. */
beb_error_t beb_individual_secrets(const uint8_t secret[32],
                                   const beb_pubkey_t *keys,
                                   size_t keys_count,
                                   beb_secret_t **secrets_out,
                                   size_t *secrets_count_out);
/* Encrypt arbitrary data using AES-GCM-256 with the given secret and nonce. */
beb_error_t beb_encrypt_with_nonce(const uint8_t secret[32],
                                   const uint8_t *data,
                                   size_t data_len,
                                   const uint8_t nonce[12],
                                   uint8_t **ciphertext_out,
                                   size_t *ciphertext_len_out);
/* Attempt AES-GCM-256 decryption and return BEB_ERROR_WRONG_KEY on auth failure. */
beb_error_t beb_try_decrypt_aes_gcm_256(const uint8_t *ciphertext,
                                        size_t ciphertext_len,
                                        const uint8_t secret[32],
                                        const uint8_t nonce[12],
                                        uint8_t **plaintext_out,
                                        size_t *plaintext_len_out);

/* Encode a list of derivation paths into the compact v1 serialized format. */
beb_error_t beb_encode_derivation_paths(const beb_derivation_path_t *paths,
                                        size_t paths_count,
                                        uint8_t **out,
                                        size_t *out_len);
/* Encode a set of individual secrets, removing duplicates along the way. */
beb_error_t beb_encode_individual_secrets(const beb_secret_t *secrets,
                                          size_t secrets_count,
                                          uint8_t **out,
                                          size_t *out_len);
/* Encode nonce and ciphertext into the v1 encrypted payload format. */
beb_error_t beb_encode_encrypted_payload(const uint8_t nonce[12],
                                         const uint8_t *cyphertext,
                                         size_t cyphertext_len,
                                         uint8_t **out,
                                         size_t *out_len);
/* Assemble the full BEB v1 container from its encoded components. */
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

/* Parse and validate the BEB magic prefix, returning the new offset. */
beb_error_t beb_parse_magic_byte(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out);
/* Parse and validate the encoded version byte at the beginning of a payload. */
beb_error_t beb_parse_version(const uint8_t *bytes,
                              size_t bytes_len,
                              size_t *offset_out,
                              uint8_t *version_out);
/* Parse the encryption algorithm byte from the payload. */
beb_error_t beb_parse_encryption(const uint8_t *bytes,
                                 size_t bytes_len,
                                 size_t *offset_out,
                                 uint8_t *encryption_out);
/* Parse and allocate an array of derivation paths from the payload. */
beb_error_t beb_parse_derivation_paths(const uint8_t *bytes,
                                       size_t bytes_len,
                                       size_t *offset_out,
                                       beb_derivation_path_t **paths_out,
                                       size_t *paths_count_out);
/* Parse and allocate a possibly de-duplicated list of individual secrets. */
beb_error_t beb_parse_individual_secrets(const uint8_t *bytes,
                                         size_t bytes_len,
                                         size_t *offset_out,
                                         beb_secret_t **secrets_out,
                                         size_t *secrets_count_out);
/* Parse the encrypted payload, returning nonce and ciphertext buffer. */
beb_error_t beb_parse_encrypted_payload(const uint8_t *bytes,
                                        size_t bytes_len,
                                        size_t *offset_out,
                                        uint8_t nonce_out[12],
                                        uint8_t **cyphertext_out,
                                        size_t *cyphertext_len_out);
/* Decode only the BEB version field from a full encoded blob. */
beb_error_t beb_decode_version(const uint8_t *bytes,
                               size_t bytes_len,
                               uint8_t *version_out);
/* Decode and allocate only the derivation paths from a full encoded blob. */
beb_error_t beb_decode_derivation_paths(const uint8_t *bytes,
                                        size_t bytes_len,
                                        beb_derivation_path_t **paths_out,
                                        size_t *paths_count_out);
/* Decode all structured fields from a BEB v1-encoded blob into result_out. */
beb_error_t beb_decode_v1(const uint8_t *bytes,
                          size_t bytes_len,
                          beb_decode_v1_result_t *result_out);

/* Encrypt data into a BEB v1 AES-GCM-256 backup with explicit nonce control. */
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

void beb_derivation_paths_free(beb_derivation_path_t *paths, size_t count);
void beb_decode_v1_result_free(beb_decode_v1_result_t *result);
void beb_decrypt_result_free(beb_decrypt_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BEB_H */
