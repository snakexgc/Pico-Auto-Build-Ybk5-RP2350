/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "serial.h"
#include "pico_time.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/sha256.h"
#include "credential.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "hid/ctap_hid.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"
#include "files.h"
#include "otp.h"
#include "resident_container.h"

int credential_derive_chacha_key(uint8_t *outk, const uint8_t *);

#define RP_RECORD_COUNT_LEN                 1
#define RP_RECORD_HASH_LEN                  32
#define RP_RECORD_HEADER_LEN                (RP_RECORD_COUNT_LEN + RP_RECORD_HASH_LEN)
#define RP_SECURE_OVERHEAD                  (CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN)

static void credential_rp_id_iv(const uint8_t *rp_id_hash, uint8_t iv[CRED_IV_LEN]) {
    uint8_t digest[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, (const uint8_t *) CRED_PROTO_RP_S, CRED_PROTO_LEN);
    mbedtls_sha256_update(&ctx, rp_id_hash, RP_RECORD_HASH_LEN);
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
    memcpy(iv, digest, CRED_IV_LEN);
    mbedtls_platform_zeroize(digest, sizeof(digest));
}

static bool credential_rp_id_is_secure(const file_t *ef) {
    if (!file_has_data(ef) || file_get_size(ef) < RP_RECORD_HEADER_LEN + RP_SECURE_OVERHEAD) {
        return false;
    }
    return memcmp(file_get_data(ef) + RP_RECORD_HEADER_LEN, CRED_PROTO_RP_S, CRED_PROTO_LEN) == 0;
}

static int credential_rp_id_encrypt(const uint8_t *rp_id_hash, const uint8_t *rp_id, size_t rp_id_len, uint8_t **out, size_t *out_len) {
    uint8_t key[32] = {0};
    uint8_t iv[CRED_IV_LEN] = {0};
    int ret = credential_derive_chacha_key(key, (const uint8_t *)CRED_PROTO_RP_S);
    if (ret != 0) {
        return ret;
    }
    *out_len = CRED_PROTO_LEN + CRED_IV_LEN + rp_id_len + CRED_TAG_LEN;
    *out = (uint8_t *) calloc(1, *out_len);
    if (*out == NULL) {
        mbedtls_platform_zeroize(key, sizeof(key));
        return -1;
    }
    memcpy(*out, CRED_PROTO_RP_S, CRED_PROTO_LEN);
    credential_rp_id_iv(rp_id_hash, iv);
    memcpy(*out + CRED_PROTO_LEN, iv, CRED_IV_LEN);

    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rp_id_len, iv, rp_id_hash, RP_RECORD_HASH_LEN, rp_id, *out + CRED_PROTO_LEN + CRED_IV_LEN, *out + CRED_PROTO_LEN + CRED_IV_LEN + rp_id_len);
    mbedtls_chachapoly_free(&chatx);
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    if (ret != 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
    }
    return ret;
}

int credential_rp_id_decrypt(const file_t *ef, uint8_t **rp_id, size_t *rp_id_len) {
    if (!file_has_data(ef) || file_get_size(ef) < RP_RECORD_HEADER_LEN) {
        return -1;
    }
    uint8_t *record = file_get_data(ef);
    uint16_t record_len = file_get_size(ef);
    uint8_t *tail = record + RP_RECORD_HEADER_LEN;
    size_t tail_len = record_len - RP_RECORD_HEADER_LEN;
    *rp_id = NULL;
    *rp_id_len = 0;

    if (!credential_rp_id_is_secure(ef)) {
        *rp_id = (uint8_t *) calloc(1, tail_len + 1);
        if (*rp_id == NULL) {
            return -1;
        }
        memcpy(*rp_id, tail, tail_len);
        *rp_id_len = tail_len;
        return 0;
    }

    if (tail_len < RP_SECURE_OVERHEAD) {
        return -1;
    }
    size_t plaintext_len = tail_len - RP_SECURE_OVERHEAD;
    *rp_id = (uint8_t *) calloc(1, plaintext_len + 1);
    if (*rp_id == NULL) {
        return -1;
    }

    uint8_t key[32] = {0};
    int ret = credential_derive_chacha_key(key, (const uint8_t *) CRED_PROTO_RP_S);
    if (ret == 0) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, plaintext_len, tail + CRED_PROTO_LEN, record + RP_RECORD_COUNT_LEN, RP_RECORD_HASH_LEN, tail + CRED_PROTO_LEN + CRED_IV_LEN + plaintext_len, tail + CRED_PROTO_LEN + CRED_IV_LEN, *rp_id);
        mbedtls_chachapoly_free(&chatx);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) {
        free(*rp_id);
        *rp_id = NULL;
        *rp_id_len = 0;
        return ret;
    }
    *rp_id_len = plaintext_len;
    return 0;
}

int credential_migrate_rp_secure(void) {
    bool changed = false;
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search((uint16_t)(EF_RP + i));
        if (!file_has_data(ef) || credential_rp_id_is_secure(ef)) {
            continue;
        }
        uint8_t *record = file_get_data(ef);
        uint16_t record_len = file_get_size(ef);
        if (record_len < RP_RECORD_HEADER_LEN) {
            continue;
        }
        uint8_t *out = NULL;
        size_t out_len = 0;
        int ret = credential_rp_id_encrypt(record + RP_RECORD_COUNT_LEN, record + RP_RECORD_HEADER_LEN, record_len - RP_RECORD_HEADER_LEN, &out, &out_len);
        if (ret != 0) {
            free(out);
            continue;
        }
        uint8_t *data = (uint8_t *)calloc(1, RP_RECORD_HEADER_LEN + out_len);
        if (data == NULL) {
            free(out);
            continue;
        }
        memcpy(data, record, RP_RECORD_HEADER_LEN);
        memcpy(data + RP_RECORD_HEADER_LEN, out, out_len);
        file_put_data(ef, data, (uint16_t)(RP_RECORD_HEADER_LEN + out_len));
        free(data);
        free(out);
        changed = true;
    }
    if (changed) {
        flash_commit();
    }
    return PICOKEYS_OK;
}

static int credential_silent_tag(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, uint8_t *outk) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    if (otp_key_1) {
        mbedtls_sha256_update(&ctx, otp_key_1, 32);
    }
    else {
        mbedtls_sha256_update(&ctx, pico_serial.id, sizeof(pico_serial.id));
    }
    if (memcmp(cred_id, CRED_PROTO_25_S, CRED_PROTO_LEN) == 0) {
        mbedtls_sha256_update(&ctx, certdev_sha256, sizeof(certdev_sha256));
    }
    mbedtls_sha256_update(&ctx, rp_id_hash, 32);
    mbedtls_sha256_finish(&ctx, outk);
    mbedtls_sha256_free(&ctx);

    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, cred_id, cred_id_len - CRED_SILENT_TAG_LEN, outk);
}

int credential_verify(uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, bool silent) {
    if (cred_id_len < 4 + 12 + 16) {
        return -1;
    }
    uint8_t key[32] = {0}, *iv = cred_id + CRED_PROTO_LEN, *cipher = cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
            *tag = cred_id + cred_id_len - CRED_TAG_LEN;
    cred_proto_t proto = CRED_PROTO_21;
    if (memcmp(cred_id, CRED_PROTO_22_S, CRED_PROTO_LEN) == 0 || memcmp(cred_id, CRED_PROTO_25_S, CRED_PROTO_LEN) == 0) { // New format
        tag = cred_id + cred_id_len - CRED_SILENT_TAG_LEN - CRED_TAG_LEN;
        proto = CRED_PROTO_25;
    }
    int ret = 0;
    if (!silent) {
        int hdr_len = CRED_PROTO_LEN + CRED_IV_LEN + CRED_TAG_LEN;
        if (proto == CRED_PROTO_22 || proto == CRED_PROTO_25) {
            hdr_len += CRED_SILENT_TAG_LEN;
        }
        credential_derive_chacha_key(key, cred_id);
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, key);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, cred_id_len - hdr_len, iv, rp_id_hash, 32, tag, cipher, cipher);
        mbedtls_chachapoly_free(&chatx);
    }
    else {
        if (proto <= CRED_PROTO_21) {
            return -1;
        }
        uint8_t outk[32];
        ret = credential_silent_tag(cred_id, cred_id_len, rp_id_hash, outk);
        ret = memcmp(outk, cred_id + cred_id_len - CRED_SILENT_TAG_LEN, CRED_SILENT_TAG_LEN);
    }
    return ret;
}

int credential_create(CborCharString *rpId, CborByteString *userId, CborCharString *userName, CborCharString *userDisplayName, CredOptions *opts, CredExtensions *extensions, bool use_sign_count, int alg, int curve, uint8_t *cred_id, uint16_t *cred_id_len) {
    CborEncoder encoder, mapEncoder, mapEncoder2;
    CborError error = CborNoError;
    uint8_t rp_id_hash[32];
    mbedtls_sha256((uint8_t *) rpId->data, rpId->len, rp_id_hash, 0);
    cbor_encoder_init(&encoder, cred_id + 4 + 12, MAX_CRED_ID_LENGTH - (4 + 12 + 16), 0);
    CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder,  CborIndefiniteLength));
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x01, *rpId);
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
    CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, rp_id_hash, 32));
    CBOR_APPEND_KEY_UINT_VAL_BYTES(mapEncoder, 0x03, *userId);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x04, *userName);
    CBOR_APPEND_KEY_UINT_VAL_STRING(mapEncoder, 0x05, *userDisplayName);
    CBOR_APPEND_KEY_UINT_VAL_UINT(mapEncoder, 0x06, board_millis());
    if (extensions->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (extensions->credBlob.present == true &&
            extensions->credBlob.len < MAX_CREDBLOB_LENGTH) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credBlob"));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder2, extensions->credBlob.data, extensions->credBlob.len));
        }
        if (extensions->credProtect != 0) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "credProtect"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder2, extensions->credProtect));
        }
        if (extensions->hmac_secret != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "hmac-secret"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, *extensions->hmac_secret));
        }
        if (extensions->largeBlobKey == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "largeBlobKey"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        if (extensions->thirdPartyPayment == ptrue) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "thirdPartyPayment"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, true));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
    CBOR_CHECK(cbor_encode_boolean(&mapEncoder, use_sign_count));
    if (alg != FIDO2_ALG_ES256 || curve != FIDO2_CURVE_P256) {
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x09, alg);
        CBOR_APPEND_KEY_UINT_VAL_INT(mapEncoder, 0x0A, curve);
    }
    if (opts->present == true) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
        CBOR_CHECK(cbor_encoder_create_map(&mapEncoder, &mapEncoder2,  CborIndefiniteLength));
        if (opts->rk != NULL) {
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder2, "rk"));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder2, opts->rk == ptrue));
        }
        CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &mapEncoder2));
    }
    if (has_set_rtc()) {
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
        CBOR_CHECK(cbor_encode_uint(&mapEncoder, (uint64_t) get_rtc_time()));
    }
    CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
    size_t rs = cbor_encoder_get_buffer_size(&encoder, cred_id);
    *cred_id_len = CRED_PROTO_LEN + CRED_IV_LEN + (uint16_t)rs + CRED_TAG_LEN + CRED_SILENT_TAG_LEN;
    uint8_t key[32] = {0};
    credential_derive_chacha_key(key, (const uint8_t *)CRED_PROTO);
    uint8_t iv[CRED_IV_LEN] = {0};
    random_fill_buffer(iv, sizeof(iv));
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, key);
    int ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, rs, iv, rp_id_hash, 32,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN,
                                                 cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs);
    mbedtls_chachapoly_free(&chatx);
    if (ret != 0) {
        CBOR_ERROR(CTAP1_ERR_OTHER);
    }
    memcpy(cred_id, CRED_PROTO, CRED_PROTO_LEN);
    memcpy(cred_id + CRED_PROTO_LEN, iv, CRED_IV_LEN);
    credential_silent_tag(cred_id, *cred_id_len, rp_id_hash, cred_id + CRED_PROTO_LEN + CRED_IV_LEN + rs + CRED_TAG_LEN);

err:
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    return 0;
}

int credential_load(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, Credential *cred) {
    int ret = 0;
    CborError error = CborNoError;
    uint8_t *copy_cred_id = (uint8_t *) calloc(1, cred_id_len);
    if (!cred) {
        CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
    }
    memset(cred, 0, sizeof(Credential));
    memcpy(copy_cred_id, cred_id, cred_id_len);
    ret = credential_verify(copy_cred_id, cred_id_len, rp_id_hash, false);
    if (ret != 0) { // U2F?
        if (cred_id_len != KEY_HANDLE_LEN || verify_key(rp_id_hash, cred_id, NULL) != 0) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CREDENTIAL);
        }
    }
    else {
        CborParser parser;
        CborValue map;
        memset(cred, 0, sizeof(Credential));
        cred->curve = FIDO2_CURVE_P256;
        cred->alg = FIDO2_ALG_ES256;
        CBOR_CHECK(cbor_parser_init(copy_cred_id + 4 + 12, cred_id_len - (4 + 12 + 16), 0, &parser, &map));
        CBOR_PARSE_MAP_START(map, 1)
        {
            uint64_t val_u = 0;
            CBOR_FIELD_GET_UINT(val_u, 1);
            if (val_u == 0x01) {
                CBOR_FIELD_GET_TEXT(cred->rpId, 1);
            }
            else if (val_u == 0x03) {
                CBOR_FIELD_GET_BYTES(cred->userId, 1);
            }
            else if (val_u == 0x04) {
                CBOR_FIELD_GET_TEXT(cred->userName, 1);
            }
            else if (val_u == 0x05) {
                CBOR_FIELD_GET_TEXT(cred->userDisplayName, 1);
            }
            else if (val_u == 0x06) {
                CBOR_FIELD_GET_UINT(cred->board_creation, 1);
            }
            else if (val_u == 0x07) {
                cred->extensions.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "hmac-secret", cred->extensions.hmac_secret);
                    CBOR_FIELD_KEY_TEXT_VAL_UINT(2, "credProtect", cred->extensions.credProtect);
                    CBOR_FIELD_KEY_TEXT_VAL_BYTES(2, "credBlob", cred->extensions.credBlob);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "largeBlobKey", cred->extensions.largeBlobKey);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "thirdPartyPayment", cred->extensions.thirdPartyPayment);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x08) {
                CBOR_FIELD_GET_BOOL(cred->use_sign_count, 1);
            }
            else if (val_u == 0x09) {
                CBOR_FIELD_GET_INT(cred->alg, 1);
            }
            else if (val_u == 0x0A) {
                CBOR_FIELD_GET_INT(cred->curve, 1);
            }
            else if (val_u == 0x0B) {
                cred->opts.present = true;
                CBOR_PARSE_MAP_START(_f1, 2)
                {
                    CBOR_FIELD_GET_KEY_TEXT(2);
                    CBOR_FIELD_KEY_TEXT_VAL_BOOL(2, "rk", cred->opts.rk);
                    CBOR_ADVANCE(2);
                }
                CBOR_PARSE_MAP_END(_f1, 2);
            }
            else if (val_u == 0x0C) {
                CBOR_FIELD_GET_UINT(cred->rtc_creation, 1);
            }
            else {
                CBOR_ADVANCE(1);
            }
        }
    }
    cred->id.present = true;
    cred->id.data = (uint8_t *) calloc(1, cred_id_len);
    memcpy(cred->id.data, cred_id, cred_id_len);
    cred->id.len = cred_id_len;
    cred->present = true;
err:
    free(copy_cred_id);
    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    return 0;
}

void credential_free(Credential *cred) {
    if (cred) {
        CBOR_FREE_BYTE_STRING(cred->rpId);
        CBOR_FREE_BYTE_STRING(cred->userId);
        CBOR_FREE_BYTE_STRING(cred->userName);
        CBOR_FREE_BYTE_STRING(cred->userDisplayName);
        CBOR_FREE_BYTE_STRING(cred->id);
        CBOR_FREE_BYTE_STRING(cred->residentId);
        if (cred->extensions.present) {
            CBOR_FREE_BYTE_STRING(cred->extensions.credBlob);
        }
        cred->present = false;
        cred->extensions.present = false;
        cred->opts.present = false;
    }
}

int credential_store(const uint8_t *cred_id, size_t cred_id_len, const uint8_t *rp_id_hash, const uint8_t *public_key, size_t public_key_len) {
    int sloti = -1;
    Credential cred = { 0 };
    int ret = 0;
    bool new_record = true;
    bool use_container = true;

    if (!cred_id || !rp_id_hash || !public_key || public_key_len == 0) {
        return -1;
    }
    ret = credential_load(cred_id, cred_id_len, rp_id_hash, &cred);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
        file_t *ef = file_search(EF_CRED + i);
        Credential rcred = { 0 };
        if (!file_has_data(ef)) {
            if (sloti == -1 && resident_container_can_create((uint8_t)i)) {
                sloti = i;
            }
            continue;
        }
        if (!credential_resident_matches_rp(ef, rp_id_hash)) {
            continue;
        }
        ret = credential_load_resident(ef, rp_id_hash, &rcred);
        if (ret != 0) {
            credential_free(&rcred);
            continue;
        }
        if (rcred.userId.len == cred.userId.len && memcmp(rcred.userId.data, cred.userId.data, rcred.userId.len) == 0) {
            sloti = i;
            credential_free(&rcred);
            new_record = false;
            use_container = resident_container_is_marker(ef);
            break;
        }
        credential_free(&rcred);
    }
    if (sloti == -1) {
        credential_free(&cred);
        return -1;
    }
    uint8_t cred_idr[CRED_RESIDENT_LEN] = {0};
    ret = credential_derive_resident(cred_id, cred_id_len, cred_idr);
    if (ret != 0) {
        credential_free(&cred);
        return ret;
    }
    uint8_t *data = NULL;
    file_t *ef = NULL;
    if (use_container) {
        ret = resident_container_create((uint8_t)sloti, rp_id_hash, cred_idr, sizeof(cred_idr), cred_id, cred_id_len, public_key, public_key_len);
    }
    else {
        data = (uint8_t *)calloc(1, cred_id_len + 32 + CRED_RESIDENT_LEN);
        if (!data) {
            credential_free(&cred);
            return -1;
        }
        memcpy(data, rp_id_hash, 32);
        memcpy(data + 32, cred_idr, CRED_RESIDENT_LEN);
        memcpy(data + 32 + CRED_RESIDENT_LEN, cred_id, cred_id_len);
        ef = file_new((uint16_t)(EF_CRED + sloti));
        ret = ef ? file_put_data(ef, data, (uint32_t)cred_id_len + 32 + CRED_RESIDENT_LEN) : PICOKEYS_ERR_NO_MEMORY;
        free(data);
    }
    if (ret != PICOKEYS_OK) {
        credential_free(&cred);
        return ret;
    }

    if (new_record == true) { //increase rps
        sloti = -1;
        for (uint16_t i = 0; i < MAX_RESIDENT_CREDENTIALS; i++) {
            ef = file_search(EF_RP + i);
            if (!file_has_data(ef)) {
                if (sloti == -1) {
                    sloti = i;
                }
                continue;
            }
            if (memcmp(file_get_data(ef) + 1, rp_id_hash, 32) == 0) {
                sloti = i;
                break;
            }
        }
        if (sloti == -1) {
            credential_free(&cred);
            return -1;
        }
        ef = file_search((uint16_t)(EF_RP + sloti));
        if (file_has_data(ef)) {
            data = (uint8_t *) calloc(1, file_get_size(ef));
            memcpy(data, file_get_data(ef), file_get_size(ef));
            data[0] += 1;
            file_put_data(ef, data, file_get_size(ef));
            free(data);
        }
        else {
            ef = file_new((uint16_t)(EF_RP + sloti));
            if (ef == NULL) {
                credential_free(&cred);
                return -1;
            }
            uint8_t *out = NULL;
            size_t out_len = 0;
            if (credential_rp_id_encrypt(rp_id_hash, (uint8_t *)cred.rpId.data, cred.rpId.len, &out, &out_len) != 0) {
                credential_free(&cred);
                return -1;
            }
            data = (uint8_t *)calloc(1, RP_RECORD_HEADER_LEN + out_len);
            if (data == NULL) {
                free(out);
                credential_free(&cred);
                return -1;
            }
            data[0] = 1;
            memcpy(data + 1, rp_id_hash, 32);
            memcpy(data + RP_RECORD_HEADER_LEN, out, out_len);
            file_put_data(ef, data, (uint16_t)(RP_RECORD_HEADER_LEN + out_len));
            free(data);
            free(out);
        }
    }
    credential_free(&cred);
    flash_commit();
    return 0;
}

int credential_derive_hmac_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 64);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "hmac-secret", 11, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_chacha_key(uint8_t *outk, const uint8_t *proto) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) (proto ? proto : (const uint8_t *)CRED_PROTO), CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "Encryption key", 14, outk);
    return 0;
}

int credential_derive_large_blob_key(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, 32);
    int r = 0;
    if ((r = load_keydev(outk)) != 0) {
        return r;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "SLIP-0022", 9, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, outk);
    mbedtls_md_hmac(md_info, outk, 32, (uint8_t *) "largeBlobKey", 12, outk);
    mbedtls_md_hmac(md_info, outk, 32, cred_id, cred_id_len, outk);
    return 0;
}

int credential_derive_resident(const uint8_t *cred_id, size_t cred_id_len, uint8_t *outk) {
    memset(outk, 0, CRED_RESIDENT_LEN);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t *cred_idr = outk + CRED_RESIDENT_HEADER_LEN;
    mbedtls_md_hmac(md_info, cred_idr, 32, pico_serial.id, sizeof(pico_serial.id), outk);
    memcpy(outk + 4, CRED_PROTO_RESIDENT, CRED_PROTO_RESIDENT_LEN);
    outk[4 + CRED_PROTO_RESIDENT_LEN] = 0x00;
    outk[4 + CRED_PROTO_RESIDENT_LEN + 1] = 0x00;

    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "SLIP-0022", 9, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) cred_id, CRED_PROTO_LEN, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, (uint8_t *) "resident", 8, cred_idr);
    mbedtls_md_hmac(md_info, cred_idr, 32, cred_id, cred_id_len, cred_idr);
    return 0;
}

bool credential_is_resident(const uint8_t *cred_id, size_t cred_id_len) {
    if (cred_id_len < 4 + CRED_PROTO_RESIDENT_LEN) {
        return false;
    }
    return memcmp(cred_id + 4, CRED_PROTO_23_S, CRED_PROTO_RESIDENT_LEN) == 0 ||
           memcmp(cred_id + 4, CRED_PROTO_26_S, CRED_PROTO_RESIDENT_LEN) == 0;
}

bool credential_resident_id_uses_stable_keys(const uint8_t *resident_id, size_t resident_id_len) {
    return resident_id_len == CRED_RESIDENT_LEN &&
           memcmp(resident_id + 4, CRED_PROTO_26_S, CRED_PROTO_RESIDENT_LEN) == 0;
}

static int credential_resident_container_read_alloc(const file_t *ef, uint16_t object_type, uint8_t **data, size_t *data_len) {
    if (!resident_container_is_marker(ef) || !data || !data_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *data = NULL;
    *data_len = 0;
    uint32_t object_size = 0;
    int ret = resident_container_object_size((uint8_t)ef->fid, object_type, &object_size);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    if (object_size > 0) {
        *data = (uint8_t *)calloc(1, object_size);
        if (!*data) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
    }
    size_t written = 0;
    ret = resident_container_read((uint8_t)ef->fid, object_type, *data, object_size, &written);
    if (ret != PICOKEYS_OK || written != object_size) {
        if (*data) {
            mbedtls_platform_zeroize(*data, object_size);
            free(*data);
            *data = NULL;
        }
        return ret == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : ret;
    }
    *data_len = written;
    return PICOKEYS_OK;
}

int credential_resident_rp_id_hash(const file_t *ef, uint8_t rp_id_hash[32]) {
    if (!file_has_data(ef) || !rp_id_hash) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!resident_container_is_marker(ef)) {
        if (file_get_size(ef) < 32) {
            return PICOKEYS_WRONG_LENGTH;
        }
        memcpy(rp_id_hash, file_get_data(ef), 32);
        return PICOKEYS_OK;
    }
    size_t written = 0;
    int ret = resident_container_read((uint8_t)ef->fid, FIDO_RESIDENT_OBJECT_RP_ID_HASH, rp_id_hash, 32, &written);
    return ret == PICOKEYS_OK && written == 32 ? PICOKEYS_OK : (ret == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : ret);
}

bool credential_resident_matches_rp(const file_t *ef, const uint8_t rp_id_hash[32]) {
    uint8_t stored_hash[32];
    return rp_id_hash && credential_resident_rp_id_hash(ef, stored_hash) == PICOKEYS_OK && mbedtls_ct_memcmp(stored_hash, rp_id_hash, sizeof(stored_hash)) == 0;
}

bool credential_resident_matches_id(const file_t *ef, const uint8_t *resident_id, size_t resident_id_len) {
    if (!file_has_data(ef) || !resident_id || resident_id_len != CRED_RESIDENT_LEN) {
        return false;
    }
    uint8_t stored_id[CRED_RESIDENT_LEN];
    if (resident_container_is_marker(ef)) {
        size_t written = 0;
        if (resident_container_read((uint8_t)ef->fid, FIDO_RESIDENT_OBJECT_CLIENT_ID, stored_id, sizeof(stored_id), &written) != PICOKEYS_OK || written != sizeof(stored_id)) {
            return false;
        }
    }
    else if (file_get_size(ef) >= 32 + CRED_RESIDENT_LEN && credential_is_resident(file_get_data(ef) + 32, file_get_size(ef) - 32)) {
        memcpy(stored_id, file_get_data(ef) + 32, sizeof(stored_id));
    }
    else if (file_get_size(ef) > 32) {
        if (credential_derive_resident(file_get_data(ef) + 32, file_get_size(ef) - 32, stored_id) != 0) {
            return false;
        }
    }
    else {
        return false;
    }
    return mbedtls_ct_memcmp(stored_id, resident_id, sizeof(stored_id)) == 0;
}

int credential_load_resident(const file_t *ef, const uint8_t *rp_id_hash, Credential *cred) {
    if (!file_has_data(ef) || !rp_id_hash || !cred) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (resident_container_is_marker(ef)) {
        uint8_t stored_hash[32];
        if (credential_resident_rp_id_hash(ef, stored_hash) != PICOKEYS_OK || mbedtls_ct_memcmp(stored_hash, rp_id_hash, sizeof(stored_hash)) != 0) {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        uint8_t *credential = NULL;
        uint8_t *resident_id = NULL;
        size_t credential_len = 0;
        size_t resident_id_len = 0;
        int ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CREDENTIAL, &credential, &credential_len);
        if (ret == PICOKEYS_OK) {
            ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CLIENT_ID, &resident_id, &resident_id_len);
        }
        if (ret == PICOKEYS_OK && resident_id_len != CRED_RESIDENT_LEN) {
            ret = PICOKEYS_WRONG_LENGTH;
        }
        if (ret == PICOKEYS_OK) {
            ret = credential_load(credential, credential_len, rp_id_hash, cred);
        }
        if (ret == 0) {
            cred->residentId.present = true;
            cred->residentId.len = resident_id_len;
            cred->residentId.data = resident_id;
            resident_id = NULL;
        }
        if (credential) {
            mbedtls_platform_zeroize(credential, credential_len);
            free(credential);
        }
        free(resident_id);
        return ret;
    }
    if (file_get_size(ef) <= 32) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    if (credential_is_resident(file_get_data(ef) + 32, file_get_size(ef) - 32)) {
        int ret = credential_load(file_get_data(ef) + 32 + CRED_RESIDENT_LEN, file_get_size(ef) - 32 - CRED_RESIDENT_LEN, rp_id_hash, cred);
        if (ret == 0) {
            cred->residentId.present = true;
            cred->residentId.len = CRED_RESIDENT_LEN;
            cred->residentId.data = (uint8_t *) calloc(1, CRED_RESIDENT_LEN);
            if (cred->residentId.data == NULL) {
                credential_free(cred);
                return CTAP2_ERR_PROCESSING;
            }
            memcpy(cred->residentId.data, file_get_data(ef) + 32, CRED_RESIDENT_LEN);
        }
        return ret;
    }
    return credential_load(file_get_data(ef) + 32, file_get_size(ef) - 32, rp_id_hash, cred);
}

int credential_resident_public_key(const file_t *ef, uint8_t **public_key, size_t *public_key_len) {
    if (!public_key || !public_key_len) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!resident_container_is_marker(ef)) {
        *public_key = NULL;
        *public_key_len = 0;
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_PUBLIC_KEY, public_key, public_key_len);
}

int credential_resident_update(const file_t *ef, const uint8_t *credential, size_t credential_len) {
    if (!file_has_data(ef) || (!credential && credential_len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (resident_container_is_marker(ef)) {
        return resident_container_update_credential((uint8_t)ef->fid, credential, credential_len);
    }
    uint8_t rp_id_hash[32];
    if (credential_resident_rp_id_hash(ef, rp_id_hash) != PICOKEYS_OK) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t resident_id[CRED_RESIDENT_LEN];
    if (file_get_size(ef) >= 32 + CRED_RESIDENT_LEN && credential_is_resident(file_get_data(ef) + 32, file_get_size(ef) - 32)) {
        memcpy(resident_id, file_get_data(ef) + 32, sizeof(resident_id));
    }
    else {
        if (file_get_size(ef) <= 32 || credential_derive_resident(file_get_data(ef) + 32, file_get_size(ef) - 32, resident_id) != 0) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    if (credential_len > SIZE_MAX - 32 - sizeof(resident_id)) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t updated_len = 32 + sizeof(resident_id) + credential_len;
    uint8_t *updated = (uint8_t *)calloc(1, updated_len);
    if (!updated) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    memcpy(updated, rp_id_hash, sizeof(rp_id_hash));
    memcpy(updated + 32, resident_id, sizeof(resident_id));
    memcpy(updated + 32 + sizeof(resident_id), credential, credential_len);
    int ret = file_put_data((file_t *)ef, updated, (uint32_t)updated_len);
    mbedtls_platform_zeroize(updated, updated_len);
    free(updated);
    return ret;
}

int credential_resident_delete(const file_t *ef) {
    if (!file_has_data(ef)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (resident_container_is_marker(ef)) {
        return resident_container_delete((uint8_t)ef->fid);
    }
    return file_delete((file_t *)ef);
}

int credential_resident_verify(const file_t *ef, const uint8_t rp_id_hash[32], bool silent) {
    if (!file_has_data(ef) || !rp_id_hash) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!resident_container_is_marker(ef)) {
        if (file_get_size(ef) <= 32) {
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        size_t offset = credential_is_resident(file_get_data(ef) + 32, file_get_size(ef) - 32) ? 32 + CRED_RESIDENT_LEN : 32;
        return credential_verify(file_get_data(ef) + offset, file_get_size(ef) - offset, rp_id_hash, silent);
    }
    uint8_t *credential = NULL;
    size_t credential_len = 0;
    int ret = credential_resident_container_read_alloc(ef, FIDO_RESIDENT_OBJECT_CREDENTIAL, &credential, &credential_len);
    if (ret == PICOKEYS_OK) {
        ret = credential_verify(credential, credential_len, rp_id_hash, silent);
    }
    if (credential) {
        mbedtls_platform_zeroize(credential, credential_len);
        free(credential);
    }
    return ret;
}
