/**
 * \brief OpenSSL ENGINE callback functions for ECC key management.
 *      See reference code at ec_pmeth.c and crypto/evp/evp_locl.h
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "eccx08_engine.h"
#include "eccx08_engine_internal.h"

#include <string.h>

/* Additional OpenSSL Headers */
#include <openssl/evp.h>

#ifdef ECC_DEBUG
#define ECCX08_KEY_DEBUG
#endif

#ifdef ECCX08_KEY_DEBUG
#pragma message("Warning: DANGER! This prints key material to stdout - ONLY USE FOR DEBUGGING")
#endif

/* Here comes a dirty hack because OpenSSL guys implemented EVP_PKEY_set1_engine only in 1.1.0g,
 * but Debian stretch has 1.1.0f */
#if OPENSSL_VERSION >= 0x10100000 && OPENSSL_VERSION < 0x1010007fL
struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    ENGINE *pmeth_engine; /* If not NULL public key ENGINE to use */
    union {
        void *ptr;
        struct ec_key_st *ec;   /* ECC */
    } pkey;
    int save_parameters;
};
typedef struct evp_pkey_st EVP_PKEY;

int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *e)
{
    if (e != NULL) {
        if (!ENGINE_init(e)) {
            /* EVPerr(EVP_F_EVP_PKEY_SET1_ENGINE, ERR_R_ENGINE_LIB); */
            return 0;
        }
        if (ENGINE_get_pkey_meth(e, pkey->type) == NULL) {
            ENGINE_finish(e);
            /* EVPerr(EVP_F_EVP_PKEY_SET1_ENGINE, EVP_R_UNSUPPORTED_ALGORITHM); */
            return 0;
        }
    }
    ENGINE_finish(pkey->pmeth_engine);
    pkey->pmeth_engine = e;
    return 1;
}
#endif


static struct _eccx08_pkey_def_f {
    int(*init) (EVP_PKEY_CTX *ctx);
    int(*paramgen_init) (EVP_PKEY_CTX *ctx);
    int(*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*keygen_init) (EVP_PKEY_CTX *ctx);
    int(*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*sign_init) (EVP_PKEY_CTX *ctx);
    int(*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen);
    int(*derive_init) (EVP_PKEY_CTX *ctx);
    int(*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
} eccx08_pkey_def_f;

/** \brief Key information for the device stored as an ECC private key */
int eccx08_eckey_init(eccx08_engine_key_t * cfg)
{
    if (cfg)
    {
        cfg->magic[0] = 'A';
        cfg->magic[1] = 'T';
        cfg->magic[2] = 'E';
        cfg->magic[3] = 'C';
        cfg->magic[4] = 'C';
        cfg->magic[5] = 'x';
        cfg->magic[6] = '0';
        cfg->magic[7] = '8';

        cfg->bus_type = 0;
        cfg->bus_num = 0;
        cfg->device_num = 0xC0;
        cfg->slot_num = eccx08_engine_config.device_key_slot;

        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        return ENGINE_OPENSSL_FAILURE;
    }
}

int eccx08_eckey_string_to_struct(eccx08_engine_key_t * out, const char* in, uint8_t passwd_id)
{
    if (!out || !in)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    eccx08_eckey_init(out);

    if (4 == sscanf(in, "ATECCx08:%02hhx:%02hhx:%02hhx:%02hhx", &out->bus_type,
        &out->bus_num, &out->device_num, &out->slot_num))
    {
        out->password_id = passwd_id;
        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        return ENGINE_OPENSSL_FAILURE;
    }
}

/** \brief Allocate and initialize a new ECKEY  */
static EVP_PKEY* eccx08_eckey_new_key(ENGINE *e, const char* key_id, uint8_t passwd_id)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    EVP_PKEY *  pkey;
    EC_KEY *    eckey = NULL;
    BIGNUM *    bn = NULL;

    DEBUG_ENGINE("Entered\n");

    pkey = EVP_PKEY_new();
    if(!pkey)
    {
        return NULL;
    }

    do
    {
        EC_GROUP *  group = NULL;
        eccx08_engine_key_t  key_info;

        if (key_id)
        {
            if (!eccx08_eckey_string_to_struct(&key_info, key_id, passwd_id))
            {
                break;
            }
        }
        else
        {
            if (!eccx08_eckey_init(&key_info))
            {
                break;
            }
        }

        /* allocate new EC key with our engine */
#if ATCA_OPENSSL_OLD_API
        eckey = EC_KEY_new();
#else
        eckey = EC_KEY_new_method(e);
#endif
        if (!eckey)
        {
            break;
        }

        /* set group */
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group)
        {
            break;
        }

        /* configure and assign group */
        EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        EC_KEY_set_group(eckey, group);
        EC_GROUP_free(group);

        /* Note: After this point eckey is associated with pkey and will be
        freed when pkey is freed */
        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        {
            EC_KEY_free(eckey);
            break;
        }


        /* Connect the basics */
#if ATCA_OPENSSL_OLD_API
        pkey->type = EVP_PKEY_EC;

        if (!ENGINE_init(e))
        {
            break;
        }
        pkey->engine = e;

        pkey->ameth = EVP_PKEY_asn1_find(&e, EVP_PKEY_EC);
#endif

        /* Convert the key info into a bignum */
        if (NULL == (bn = BN_bin2bn((uint8_t*)&key_info, sizeof(key_info), NULL)))
        {
            break;
        }

        /* Save the key info as the private key value */
        if (!EC_KEY_set_private_key(eckey, bn))
        {
            BN_free(bn);
            break;
        }

        /* Set method information */
#if ATCA_OPENSSL_OLD_API
        if (!ECDSA_set_method(eckey, eccx08_ecdsa_method()))
#else
        if (!EC_KEY_set_method(eckey, eccx08_ec_method()))
#endif
        {
            DEBUG_ENGINE("Failed to set ECDSA methodes to key\n");
            break;
        }

        ret = ENGINE_OPENSSL_SUCCESS;
    } while (0);

    if (ENGINE_OPENSSL_FAILURE == ret)
    {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
    }

    return (pkey);
}

/** \brief Check if the eckey provided is one that has been created by/for
the engine */
int eccx08_eckey_isx08key(EC_KEY * ec, uint8_t *passwd_id)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    const BIGNUM* bn = EC_KEY_get0_private_key(ec);

    if (bn)
    {
        uint8_t buf[32];
        uint8_t buf_ok = 0;
#if ATCA_OPENSSL_OLD_API
        if (bn->dmax * sizeof(BN_ULONG) <= sizeof(buf))
        {
            if (BN_bn2bin(bn, buf))
            {
                buf_ok = 1;
            }
        }
#else
        if (BN_bn2binpad(bn, buf, sizeof (buf)))
        {
            buf_ok = 1;
        }
#endif

        if (buf_ok && !memcmp(buf, "ATECCx08", 8))
        {
            if (passwd_id != NULL) {
                eccx08_engine_key_t *keyinfo = (eccx08_engine_key_t *) buf;
                *passwd_id = keyinfo->password_id;
            }
            ret = ENGINE_OPENSSL_SUCCESS;
        }
    }
    return ret;
}

/** \brief Check if the pkey provided is one that has been created by/for
the engine */
int eccx08_pkey_isx08key(EVP_PKEY * pkey, uint8_t *passwd_id)
{
    int ret = ENGINE_OPENSSL_FAILURE;

    if (pkey)
    {
        EC_KEY * ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key)
        {
            ret = eccx08_eckey_isx08key(ec_key, passwd_id);
            EC_KEY_free(ec_key);
        }
    }
    return ret;
}

void eccx08_eckey_debug(BIO * bio, EC_KEY * ec)
{
#ifdef ECCX08_KEY_DEBUG
    BIO * out = bio ? bio : BIO_new_fp(stdout, BIO_NOCLOSE);

    if (out)
    {
        EC_KEY_print(out, ec, 0);

        if (!bio)
        {
            BIO_free(out);
        }
    }
#endif
}

void eccx08_pkey_debug(BIO * bio, EVP_PKEY * pkey)
{
#ifdef ECCX08_KEY_DEBUG
    EC_KEY * ec = EVP_PKEY_get1_EC_KEY(pkey);

    if (ec)
    {
        eccx08_eckey_debug(bio, ec);
        EC_KEY_free(ec);
    }
#endif
}

void eccx08_pkey_ctx_debug(BIO * bio, EVP_PKEY_CTX *ctx)
{
#ifdef ECCX08_KEY_DEBUG
    BIO * out = bio ? bio : BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY * pkey;

    if (out)
    {
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (pkey)
        {
            eccx08_pkey_debug(out, pkey);
        }

        pkey = EVP_PKEY_CTX_get0_peerkey(ctx);
        if (pkey)
        {
            eccx08_pkey_debug(out, pkey);
        }

        if (!bio)
        {
            BIO_free(out);
        }
    }
#endif
}

/**
* \brief Converts raw 64 bytes of public key (ATECC508 format) to the
*  openssl EC_KEY structure. It allocates EC_KEY structure and
*  does not free it (must be a caller to free)
*
* \param[out] pEckey Pointer to EC_KEY with Public Key on success
* \param[in] pPubkeyRaw Raw public key, 64 bytes length 32-byte X following with 32-byte Y
* \return 1 on success, 0 on error
*/
static int eccx08_eckey_convert(EC_KEY *pEcKey, uint8_t *pPubKeyRaw, size_t pubkeylen)
{
    int         rv = ENGINE_OPENSSL_FAILURE;
    EC_POINT *  point = NULL;

    if (!pEcKey || !pPubKeyRaw)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    /* Rationality checks */
    if ((POINT_CONVERSION_UNCOMPRESSED != pPubKeyRaw[0]) ||
        (ATCA_BLOCK_SIZE * 2 + 1 != pubkeylen))
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    do
    {
        /* Get the group from the EC_KEY */
        const EC_GROUP *group = EC_KEY_get0_group(pEcKey);

        /* Check that the group is allocated and configured correctly */
        if (!group)
        {
            EC_GROUP *newgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            if (newgroup)
            {
                EC_GROUP_set_point_conversion_form(newgroup, POINT_CONVERSION_UNCOMPRESSED);
                EC_GROUP_set_asn1_flag(newgroup, OPENSSL_EC_NAMED_CURVE);

                if (!EC_KEY_set_group(pEcKey, newgroup))
                {
                    break;
                }

                /* Since set_group makes a copy of it we have to free the temporary */
                EC_GROUP_free(newgroup);

                /* Read new group */
                group = EC_KEY_get0_group(pEcKey);
                if (!group)
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }

        /* Allocate a public key from the group - this trusts that if one was provided its correct */
        point = EC_POINT_new(group);

        /* Use the openssl octect to point conversion routine to convert the raw format */
        if (EC_POINT_oct2point(group, point, pPubKeyRaw, pubkeylen, NULL))
        {
            EC_KEY_set_public_key(pEcKey, point);
            rv = ENGINE_OPENSSL_SUCCESS;
        }
    } while (0);

    /* Free temporary resources */
    if (point)
    {
        EC_POINT_free(point);
    }

    return (rv);
}

/**
 *
 * \brief Allocates the EVP_PKEY structure and load the ECC
 *        public key returned by the ECCX08 chip
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our case).
 * \param[in] key_id - a string for key ID (not used by the ateccx08 engine)
 * \param[in] ui_method - a pointer to the UI_METHOD structure
 *       (not used by the ateccx08 engine)
 * \param[in] callback_data - an optional parameter to provide
 *       the callback data (used to provide passwords for example)
 * \return EVP_PKEY for success, NULL otherwise
 */
static EVP_PKEY* eccx08_load_pubkey_internal(ENGINE *e, EVP_PKEY * pkey, const char* key_id,
            uint8_t passwd_id)
{
    ATCA_STATUS     status = ATCA_GEN_FAIL;
    EC_KEY *        eckey = NULL;
    int             pkey_is_ours = 0;

    DEBUG_ENGINE("Entered\n");
    if (!pkey)
    {
        pkey = eccx08_eckey_new_key(e, key_id, passwd_id);
        if (!pkey)
        {
            DEBUG_ENGINE("Failed\n");
            return NULL;
        }
        pkey_is_ours = 1;
    }

    do
    {
        uint8_t raw_pubkey[ATCA_BLOCK_SIZE * 2 + 1];
        uint8_t slot_num = 255;

        eckey = EVP_PKEY_get1_EC_KEY(pkey);

        if (!eckey)
        {
            DEBUG_ENGINE("Failed\n");
            break;
        }

        /* Openssl raw key has a leading byte with conversion form id */
        raw_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;

        /* get device */
        status = atcab_init_from_privkey_safe(eckey, &slot_num);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("ATECC init failed\n");
            break;
        }
        DEBUG_ENGINE("Got ATECC\n");

        /* Authorize if it is required */
        if (passwd_id != NOPASSWD_ID) {
            eccx08_engine_key_password_t *password = eccx08_get_password(passwd_id);
            status = eccx08_auth_password(password);
            if (status != ATCA_SUCCESS) {
                DEBUG_ENGINE("ATECC auth failed\n");
                if (ATCA_SUCCESS != atcab_release_safe()) {
                    DEBUG_ENGINE("Failed to release, result 0x%x\n", status);
                }
                break;
            }
        }

        /* Get public key without private key generation */
        status = atcab_get_pubkey(slot_num, &raw_pubkey[1]);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result 0x%x\n", status);
        }

        /* Release the device before testing status */
        if (ATCA_SUCCESS != atcab_release_safe()) {
            DEBUG_ENGINE("Result 0x%x\n", status);
            break;
        }

        /* Check atcab_get_pubkey result */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Result 0x%x\n", status);
            break;
        }

        /* Convert the raw public key into OpenSSL type */
        if (!eccx08_eckey_convert(eckey, raw_pubkey, sizeof(raw_pubkey)))
        {
            DEBUG_ENGINE("Convert Failed\n");
            status = ATCA_GEN_FAIL;
            break;
        }
    } while (0);

#ifdef ECCX08_ECKEY_DEBUG
    if (eckey)
    {
        BIO * out = BIO_new_fp(stdout, BIO_NOCLOSE);
        EC_KEY_print(out, eckey, 0);
        BIO_free(out);
    }
#endif

    if (ATCA_SUCCESS != status)
    {
        if (eckey)
        {
            EC_KEY_free(eckey);
        }

        /* Only drop the reference if we created the pkey ourselves.
           eccx08_pkey_ec_init() passes a BORROWED reference obtained with
           EVP_PKEY_CTX_get0_pkey(); freeing it here made OpenSSL's own
           cleanup decrement the refcount a second time -> UAF/double-free
           (crashes the calling process). */
        if (pkey_is_ours && pkey)
        {
            EVP_PKEY_free(pkey);
        }
        pkey = NULL;
    }

    return (pkey);
}

/** \brief Allocate an EVP_PKEY structure and initialize it
This is through the public key API */
EVP_PKEY* eccx08_load_pubkey(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data)
{
    DEBUG_ENGINE("Entered\n");
    eccx08_engine_key_password_t tmp_passwd;

    if (eccx08_cbdata_to_password(callback_data, &tmp_passwd)) {
        uint8_t passwd_id = eccx08_make_password();
        eccx08_engine_key_password_t *passwd = eccx08_get_password(passwd_id);
        memcpy(passwd, &tmp_passwd, sizeof (tmp_passwd));
        return eccx08_load_pubkey_internal(e, NULL, key_id, passwd_id);
    } else {
        return eccx08_load_pubkey_internal(e, NULL, key_id, NOPASSWD_ID);
    }
}

/** \brief Allocate an EVP_PKEY structure and initialize it
    This is through the private key API */
EVP_PKEY* eccx08_load_privkey(ENGINE *e, const char *key_id,
    UI_METHOD *ui_method, void *callback_data)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_engine_key_password_t tmp_passwd;
    if (eccx08_cbdata_to_password(callback_data, &tmp_passwd)) {
        uint8_t passwd_id = eccx08_make_password();
        eccx08_engine_key_password_t *passwd = eccx08_get_password(passwd_id);
        memcpy(passwd, &tmp_passwd, sizeof (tmp_passwd));
        return eccx08_load_pubkey_internal(e, NULL, key_id, passwd_id);
    } else {
        return eccx08_load_pubkey_internal(e, NULL, key_id, NOPASSWD_ID);
    }
}


/** \brief Intercept key initialization and see if the incomming context is a
saved key specific for this device */
int eccx08_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");

    if (ctx)
    {
        /* Check if the key is actually meta data pertaining to an ATECCx08
            device configuration */
        uint8_t passwd_id = NOPASSWD_ID;
        if (eccx08_pkey_isx08key(EVP_PKEY_CTX_get0_pkey(ctx), &passwd_id))
        {
            /* Load the public key from the device - OpenSSL would have already
            checked the key against a cert if it was asked to use the cert so
            this may be redundant depending on the use */
            if (!eccx08_load_pubkey_internal(eccx08_engine(),
                EVP_PKEY_CTX_get0_pkey(ctx), NULL, passwd_id))
            {
                return ENGINE_OPENSSL_FAILURE;
            }
        }
    }

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.init ? eccx08_pkey_def_f.init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}

#if ATCA_OPENSSL_OLD_API
/** \brief Initialize the key generation method. A placeholder in our case */
static int eccx08_eckey_paramgen_init(EVP_PKEY_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.paramgen_init ? eccx08_pkey_def_f.paramgen_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}

/** \brief Initialize the key generation method. A placeholder in our case */
static int eccx08_eckey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY * pkey)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.paramgen ? eccx08_pkey_def_f.paramgen(ctx, pkey)
        : ENGINE_OPENSSL_SUCCESS;
}
#endif

/** \brief Initialize the key generation method. A placeholder in our case */
static int eccx08_pkey_ec_keygen_init(EVP_PKEY_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.keygen_init ? eccx08_pkey_def_f.keygen_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}

/**
 *
 * \brief Generates the ECC private/public key pair. If the key
 * is locked in the TLS_SLOT_AUTH_PRIV then we just derive the
 * public key. If the key is not locked then it is
 * generated/regenerated.
 *
 * \param[in] ctx - a pointer to the EVP_PKEY_CTX
 * \param[out] pkey - a pointer to the generated EVP_PKEY
 * \return 1 for success
 */
static int eccx08_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    int rv = ENGINE_OPENSSL_FAILURE;
    EC_KEY *eckey = NULL;
    EC_GROUP * group = NULL;

    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t raw_pubkey[ATCA_BLOCK_SIZE * 2 + 1];

    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    if (!ctx || !pkey)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    /* Note: After this point eckey is associated with pkey and will be
        freed when pkey is freed */
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    do
    {
        if (EVP_PKEY_CTX_get0_pkey(ctx))
        {
            if (!EVP_PKEY_copy_parameters(pkey, EVP_PKEY_CTX_get0_pkey(ctx)))
            {
                break;
            }
        }

        /* Grab the device */
        status = atcab_init_safe(pCfg);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Openssl raw key has a leading byte with conversion form id */
        raw_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;

        //Re-generate private key and return public key
        status = atcab_genkey(eccx08_engine_config.device_key_slot,
            &raw_pubkey[1]);

        if (status != ATCA_SUCCESS) {
            //Get public key without private key generation
            status = atcab_get_pubkey(eccx08_engine_config.device_key_slot,
                &raw_pubkey[1]);
        }

        if (ATCA_SUCCESS != atcab_release_safe()) {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Check atcab_get_pubkey result */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Result %d\n", status);
            break;
        }

        /* Convert from raw bytes to OpenSSL key */
        rv = eccx08_eckey_convert(eckey, raw_pubkey, sizeof(raw_pubkey));
        if (!rv)
        {
            DEBUG_ENGINE("Error in eccx08_eckey_convert \n");
        }
        rv = ENGINE_OPENSSL_SUCCESS;
    } while (0);

    return rv;
}

static int eccx08_pkey_ec_sign_init(EVP_PKEY_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.sign_init ? eccx08_pkey_def_f.sign_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}

static int eccx08_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
    size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

#if !ATCA_OPENSSL_ENGINE_REGISTER_ECDSA
    if (eccx08_pkey_isx08key(EVP_PKEY_CTX_get0_pkey(ctx)))
    {
        int ret = ENGINE_OPENSSL_FAILURE;
        EC_KEY * ec = EVP_PKEY_get1_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
        ECDSA_SIG *ecs = NULL;

        do
        {
            if (siglen)
            {
                /* Return required signature length */
                if (!sig) {
                    *siglen = ECDSA_size(ec);
                    ret = ENGINE_OPENSSL_SUCCESS;
                    break;
                }
                else if (*siglen < (size_t)ECDSA_size(ec)) {
                    ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
                    break;
                }
            }
            else
            {
                /* Invalid call method */
                break;
            }

            ecs = eccx08_ecdsa_do_sign(tbs, tbslen, NULL, NULL, ec);

            *siglen = ecs ? i2d_ECDSA_SIG(ecs, &sig): 0;

            ret = ENGINE_OPENSSL_SUCCESS;
        } while (0);

        if (ecs)
        {
            ECDSA_SIG_free(ecs);
        }

        if (ec)
        {
            EC_KEY_free(ec);
        }

        return ret;
    }
    else
#endif
    {
        return eccx08_pkey_def_f.sign ?
            eccx08_pkey_def_f.sign(ctx, sig, siglen, tbs, tbslen)
            : ENGINE_OPENSSL_SUCCESS;
    }
}

static int eccx08_eckey_derive_init(EVP_PKEY_CTX *ctx)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

    return eccx08_pkey_def_f.derive_init ? eccx08_pkey_def_f.derive_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}

static int eccx08_eckey_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
    size_t *keylen)
{
    DEBUG_ENGINE("Entered\n");

    eccx08_pkey_ctx_debug(NULL, ctx);

        return eccx08_pkey_def_f.derive ?
            eccx08_pkey_def_f.derive(ctx, key, keylen)
            : ENGINE_OPENSSL_SUCCESS;
}

static EVP_PKEY_METHOD * eccx08_pkey_meth;

static int eccx08_pkey_meth_ids[] = { EVP_PKEY_EC, 0 };

/**
 *
 * \brief Initialize the EVP_PKEY_METHOD method callback for
 *        ateccx08 engine. Just returns a pointer to
 *        EVP_PKEY_METHOD eccx08_pkey_meth
 *
 * \param[in] e - a pointer to the engine (ateccx08 in our case).
 * \param[out] pkey_meth - a double pointer to EVP_PKEY_METHOD
 *       to return the EVP_PKEY_METHOD eccx08_pkey_meth
 * \param[out] nids - a double pointer to return an array of nid's (we return 0)
 * \param[in] nid - a number of expected nid's (we ignore this parameter)
 * \return 1 for success
 */
int eccx08_pmeth_selector(ENGINE *e, EVP_PKEY_METHOD **pkey_meth,
                       const int **nids, int nid)
{
    DEBUG_ENGINE("Entered\n");
    if (!pkey_meth) {
        *nids = eccx08_pkey_meth_ids;
        return 1;
    }

    if (EVP_PKEY_EC == nid)
    {
        *pkey_meth = eccx08_pkey_meth;
        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        *pkey_meth = NULL;
        return ENGINE_OPENSSL_FAILURE;
    }
}

#if ATCA_OPENSSL_OLD_API
/* These are from the OpenSSL 1.1.x API */
 void EVP_PKEY_meth_get_init(EVP_PKEY_METHOD *pmeth,
    int(**pinit) (EVP_PKEY_CTX *ctx))
{
    if (pmeth && pinit)
    {
        *pinit = pmeth->init;
    }
}

 void EVP_PKEY_meth_get_keygen(EVP_PKEY_METHOD *pmeth,
    int(**pkeygen_init) (EVP_PKEY_CTX *ctx),
    int(**pkeygen) (EVP_PKEY_CTX *ctx,
        EVP_PKEY *pkey))
{
    if (pmeth)
    {
        if (pkeygen_init)
        {
            *pkeygen_init = pmeth->keygen_init;
        }
        if (pkeygen)
        {
            *pkeygen = pmeth->keygen;
        }
    }
}

 void EVP_PKEY_meth_get_sign(EVP_PKEY_METHOD *pmeth,
    int(**psign_init) (EVP_PKEY_CTX *ctx),
    int(**psign) (EVP_PKEY_CTX *ctx,
        unsigned char *sig, size_t *siglen,
        const unsigned char *tbs,
        size_t tbslen))
{
    if (pmeth)
    {
        if (psign_init)
        {
            *psign_init = pmeth->sign_init;
        }
        if (psign)
        {
            *psign = pmeth->sign;
        }
    }
}

 void EVP_PKEY_meth_get_derive(EVP_PKEY_METHOD *pmeth,
    int(**pderive_init) (EVP_PKEY_CTX *ctx),
    int(**pderive) (EVP_PKEY_CTX *ctx,
        unsigned char *key,
        size_t *keylen))
{
    if (pmeth)
    {
        if (pderive_init)
        {
            *pderive_init = pmeth->derive_init;
        }
        if (pderive)
        {
            *pderive = pmeth->derive;
        }
    }
}
#endif


#if !ATCA_OPENSSL_OLD_API

static EC_KEY_METHOD * eccx08_ec;
static const EC_KEY_METHOD * eccx08_ec_default;

const EC_KEY_METHOD *eccx08_ec_default_method(void)
{
    return eccx08_ec_default;
}

EC_KEY_METHOD *eccx08_ec_method(void)
{
    return eccx08_ec;
}

int eccx08_ec_init(EC_KEY_METHOD ** ppMethod)
{
    DEBUG_ENGINE("Entered\n");

    if (!eccx08_ec_default)
    {
        eccx08_ec_default = EC_KEY_get_default_method();
    }

    if (!eccx08_ec)
    {
        eccx08_ec = EC_KEY_METHOD_new(eccx08_ec_default);
    }

    if (!eccx08_ec || !ppMethod)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    /* EC_KEY_METHOD_set_name(eccx08_ec, "ATECCX08 method"); */

#if ATCA_OPENSSL_ENGINE_ECDH
    if (!eccx08_ecdh_init_meth(eccx08_ec))
    {
        eccx08_ec_cleanup();
        return ENGINE_OPENSSL_FAILURE;
    }
#endif

#if ATCA_OPENSSL_ENGINE_ECDSA
    if (!eccx08_ecdsa_init_meth(eccx08_ec))
    {
        eccx08_ec_cleanup();
        return ENGINE_OPENSSL_FAILURE;
    }
#endif

    *ppMethod = eccx08_ec;

    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_ec_cleanup()
{
    DEBUG_ENGINE("Entered\n");
    if (eccx08_ec)
    {
        EC_KEY_METHOD_free(eccx08_ec);
        eccx08_ec = NULL;
    }

    return ENGINE_OPENSSL_SUCCESS;
}

#endif /* ATCA_OPENSSL_OLD_API */

/**
 *
 * \brief Allocate and initialize a pkey method structure for the engine
  * \return 1 for success
 */
int eccx08_pkey_meth_init(void)
{
    static const EVP_PKEY_METHOD * defaults;

    DEBUG_ENGINE("Entered\n");

    if (!eccx08_pkey_meth)
    {
        eccx08_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    }

    if (!eccx08_pkey_meth)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    defaults = EVP_PKEY_meth_find(EVP_PKEY_EC);

    /* Copy the default methods */
    EVP_PKEY_meth_copy(eccx08_pkey_meth, defaults);

    /* Retain default methods we'll be replacing */
    EVP_PKEY_meth_get_init(eccx08_pkey_meth, &eccx08_pkey_def_f.init);
    EVP_PKEY_meth_get_keygen(eccx08_pkey_meth, &eccx08_pkey_def_f.keygen_init, &eccx08_pkey_def_f.keygen);
    EVP_PKEY_meth_get_sign(eccx08_pkey_meth, &eccx08_pkey_def_f.sign_init, &eccx08_pkey_def_f.sign);
    EVP_PKEY_meth_get_derive(eccx08_pkey_meth, &eccx08_pkey_def_f.derive_init, &eccx08_pkey_def_f.derive);

    /* Replace those we need to intercept */
    EVP_PKEY_meth_set_init(eccx08_pkey_meth, eccx08_pkey_ec_init);
    EVP_PKEY_meth_set_keygen(eccx08_pkey_meth, eccx08_pkey_ec_keygen_init, eccx08_pkey_ec_keygen);
    EVP_PKEY_meth_set_sign(eccx08_pkey_meth, eccx08_pkey_ec_sign_init, eccx08_pkey_ec_sign);
    EVP_PKEY_meth_set_derive(eccx08_pkey_meth, eccx08_eckey_derive_init, eccx08_eckey_derive);

    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_pkey_meth_cleanup(void)
{
    DEBUG_ENGINE("Entered\n");
    if (eccx08_pkey_meth)
    {
        EVP_PKEY_meth_free(eccx08_pkey_meth);
        eccx08_pkey_meth = NULL;
    }
    return ENGINE_OPENSSL_SUCCESS;
}
