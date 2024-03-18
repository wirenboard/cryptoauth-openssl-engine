/**
 * \brief OpenSSL ENGINE callback functions for ECDSA Signatures and Verification
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

#include <openssl/evp.h>

#if ATCA_OPENSSL_OLD_API
static ECDSA_METHOD * eccx08_ecdsa_default;
static ECDSA_METHOD * eccx08_ecdsa;

ECDSA_METHOD *eccx08_ecdsa_method(void)
{
        return eccx08_ecdsa;
}
#endif

/**
 *
 * \brief Sends a digest to the ATECCX08 chip to generate an
 *        ECDSA signature using private key from
 *        TLS_SLOT_AUTH_PRIV slot. The private key is always
 *        stays in the chip: OpenSSL (nor any other software)
 *        has no way to read it.
 *
 * \param[in] dgst - a pointer to the buffer with a message
 *       digest (just SHA-256 is expected)
 * \param[in] dgst_len - the digest size (must be 32 bytes for
 *       ateccx08 engine)
 * \param[in] inv - a pointer to the BIGNUM structure (not used
 *       by ateccx08 engine)
 * \param[in] rp - a pointer to the BIGNUM structure (not used
 *       by ateccx08 engine)
 * \param[in] eckey - a pointer to EC_KEY structure with public
 *       ECC key and the private key token describing the
 *       private key in the ATECCX08 chip
 * \return a pointer to the ECDSA_SIG structure for success,
 *         NULL otherwise
 */
#if ATCA_OPENSSL_OLD_API
ECDSA_SIG* eccx08_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
#else
ECDSA_SIG* eccx08_ecdsa_do_sign_sig(const unsigned char *dgst, int dgst_len,
#endif
                                       const BIGNUM *inv, const BIGNUM *rp,
                                       EC_KEY *eckey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t     raw_sig[ATCA_BLOCK_SIZE * 2];
    ECDSA_SIG * sig;
    uint8_t slot_num = 255;
    uint8_t passwd_id = NOPASSWD_ID;

    DEBUG_ENGINE("Entered\n");

    /* Check Inputs */
    if (!dgst || ATCA_BLOCK_SIZE > dgst_len )
    {
        DEBUG_ENGINE("Bad Inputs: %p, %d\n", dgst, dgst_len);
        return NULL;
    }

    sig = ECDSA_SIG_new();
    if (!sig)
    {
        return NULL;
    }

    if (eccx08_eckey_isx08key(eckey, &passwd_id) != ENGINE_OPENSSL_SUCCESS)
    {
        DEBUG_ENGINE("bad ATECC ECDSA key object\n");
        return NULL;
    }

    do
    {
        /* get device */
        status = atcab_init_from_privkey_safe(eckey, &slot_num);
        if (status != ATCA_SUCCESS) {
            DEBUG_ENGINE("ATECC init failed\n");
            break;
        }
        DEBUG_ENGINE("Got ATECC\n");

        /* authorize if required */
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

        ATCAB_IDLE_TO_RESET_WATCHDOG();

        /* Do the actual signature using the configured slot */
        status = atcab_sign(slot_num, dgst, raw_sig);

        /* Make sure we release the device before checking if the sign succeeded */
        if (ATCA_SUCCESS != atcab_release_safe())
        {
            break;
        }

        /* Now check if the sign succeeded */
        if (ATCA_SUCCESS != status)
        {
            DEBUG_ENGINE("Sign Failure: %#x\n", status);
            break;
        }

        BIGNUM *r, *s;
        r = BN_bin2bn(raw_sig, ATCA_BLOCK_SIZE, NULL);
        s = BN_bin2bn(&raw_sig[ATCA_BLOCK_SIZE], ATCA_BLOCK_SIZE, NULL);
#if ATCA_OPENSSL_OLD_API
        sig->r = r;
        sig->s = s;
#else
        if (!ECDSA_SIG_set0(sig, r, s))
        {
            DEBUG_ENGINE("Failed to set ECDSA signature values\n");
            status = ATCA_FUNC_FAIL;
            break;
        }
#endif

        DEBUG_ENGINE("Succeeded\n");
    } while (0);

    if (ATCA_SUCCESS != status)
    {
        OPENSSL_free(sig);
        sig = NULL;
    }

    return (sig);
}

/**
 *
 * \brief Setup the signing method.
 *
 * \param[in] eckey A pointer to EC_KEY structure
 * \param[in] ctx A pointer to the BN_CTX structure
 * \param[in/out] kinv A double pointer to the BIGNUM
 *       structure
 * \param[in/out] r A double pointer to the BIGNUM structure
 * \return 1 for success
 */
static int eccx08_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                                   BIGNUM **r)
{
    DEBUG_ENGINE("Entered\n");
    return ENGINE_OPENSSL_SUCCESS;
}

/**
 * \brief Sign method returning blob with signature
 */
#if !ATCA_OPENSSL_OLD_API
static int eccx08_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                             unsigned char *sig, unsigned int *siglen,
                             const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    s = eccx08_ecdsa_do_sign_sig(dgst, dlen, kinv, r, eckey);
    if (!s) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    return 1;
}
#endif

/**
 *
 * \brief Verifies the digest signature.
 *
 * \param[in] dgst A pointer to the buffer with a message
 *       digest (just SHA-256 is expected)
 * \param[in] dgst_len The digest size (must be 32 bytes for
 *       ateccx08 engine)
 * \param[in] inv A pointer to the ECDSA_SIG structure with
 *       expected signature
 * \param[in] eckey A pointer to EC_KEY structure with public
 *       ECC key to verify the signature
 * \return 1 for success (signature is verified and no error is
 *         detected)
 */
#if ATCA_OPENSSL_ENGINE_ENABLE_HW_VERIFY
static int eccx08_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                                  const ECDSA_SIG *sig, EC_KEY *eckey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t *raw_pubkey = NULL;
    uint8_t *raw_sig = NULL;
    uint16_t sig_len = ATCA_BLOCK_SIZE * 2;
    size_t len;
    const EC_GROUP *group;
    point_conversion_form_t form;
    bool verified = 0;
    const BIGNUM *r, *s;

    DEBUG_ENGINE("Entered\n");

    raw_sig = (uint8_t *)OPENSSL_malloc(sig_len);
    if (raw_sig == NULL) {
        goto done;
    }

#if ATCA_OPENSSL_OLD_API
    r = sig->r;
    s = sig->s;
#else
    ECDSA_SIG_get0(sig, &r, &s);
#endif

    len = BN_num_bytes(r);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_num_bytes(s);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_bn2bin(r, raw_sig);
    if (len > sig_len / 2) {
        goto done;
    }
    len = BN_bn2bin(s, &raw_sig[sig_len / 2]);
    if (len > sig_len / 2) {
        goto done;
    }

    group = EC_KEY_get0_group(eckey);
    form = EC_GROUP_get_point_conversion_form(group);

    /* Get the raw form length requirements */
    len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), form, NULL, len, NULL);

    raw_pubkey = (uint8_t *)OPENSSL_malloc(len);
    if (raw_pubkey == NULL) {
        goto done;
    }

    /* Convert to raw form */
    if (EC_KEY_get0_public_key(eckey)) {
        EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), form, raw_pubkey, len, NULL);
    }

    /* Grab the device */
    status = atcab_init_safe(pCfg);
    if (status != ATCA_SUCCESS) {
        DEBUG_ENGINE("Init Failure: %#x\n", status);
        goto done;
    }

    /* Perform the actual verify - OpenSSL raw format for pubkey starts with a byte for the format */
    status = atcab_verify_extern(dgst, raw_sig, &raw_pubkey[1], &verified);

    /* Release the device before testing the result */
    if (ATCA_SUCCESS != atcab_release_safe()) {
        DEBUG_ENGINE("Release Failure: %#x\n", status);
    }

done:
    /* Cleanup temporary memory allocations */
    if (raw_sig) {
        OPENSSL_free(raw_sig);
    }

    if (raw_pubkey) {
        OPENSSL_free(raw_pubkey);
    }

    DEBUG_ENGINE("Finished: %#x\n", status);

    /* Determine the proper return code */
    if (ATCA_SUCCESS != status)
    {
        return ENGINE_OPENSSL_ERROR;
    }
    else if (verified)
    {
        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        /* This is a bit different than normal OpenSSL functions as 0 means
            not verified */
        return ENGINE_OPENSSL_FAILURE;
    }
}
#endif

#if ATCA_OPENSSL_OLD_API
ECDSA_SIG* eccx08_ecdsa_sign(const unsigned char *dgst, int dgst_len,
#else
ECDSA_SIG* eccx08_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
#endif
    const BIGNUM *inv, const BIGNUM *rp,
    EC_KEY *eckey)
{
    /* Check if the provided key is a hardware key */
    if (eccx08_eckey_isx08key(eckey, NULL))
    {
#if ATCA_OPENSSL_OLD_API
        return eccx08_ecdsa_do_sign(dgst, dgst_len, inv, rp, eckey);
#else
        return eccx08_ecdsa_do_sign_sig(dgst, dgst_len, inv, rp, eckey);
#endif
    }
    else
    {
        /* Not a hardware key - compute normally */
#if ATCA_OPENSSL_OLD_API
        return eccx08_ecdsa_default->ecdsa_do_sign(dgst, dgst_len, inv, rp, eckey);
#else
        const EC_KEY_METHOD *dflt = eccx08_ec_default_method();
        /* TODO: get method pointer from there and call a function */
        ECDSA_SIG *(*dflt_meth)(const unsigned char *, int, const BIGNUM *,
                const BIGNUM *, EC_KEY *);

        EC_KEY_METHOD_get_sign(dflt, NULL, NULL, &dflt_meth);
        return dflt_meth(dgst, dgst_len, inv, rp, eckey);
#endif
    }
}

#if ATCA_OPENSSL_OLD_API

int eccx08_ecdsa_init(ECDSA_METHOD ** ppMethod)
{
    DEBUG_ENGINE("Entered\n");
    if (!eccx08_ecdsa_default)
    {
        eccx08_ecdsa_default = ECDSA_get_default_method();
    }

    if (!eccx08_ecdsa)
    {
        eccx08_ecdsa = ECDSA_METHOD_new(eccx08_ecdsa_default);
    }

    if (!eccx08_ecdsa || !ppMethod)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    ECDSA_METHOD_set_name(eccx08_ecdsa, "ATECCX08 ECDSA METHOD");
    ECDSA_METHOD_set_sign(eccx08_ecdsa, eccx08_ecdsa_sign);

#if ATCA_OPENSSL_ENGINE_ENABLE_HW_VERIFY
    ECDSA_METHOD_set_verify(eccx08_ecdsa, eccx08_ecdsa_do_verify);
#endif

    *ppMethod = eccx08_ecdsa;

    return ENGINE_OPENSSL_SUCCESS;
}

int eccx08_ecdsa_cleanup()
{
    DEBUG_ENGINE("Entered\n");
    if (eccx08_ecdsa)
    {
        ECDSA_METHOD_free(eccx08_ecdsa);
    }

    return ENGINE_OPENSSL_SUCCESS;
}

#else

int eccx08_ecdsa_init_meth(EC_KEY_METHOD *pMethod)
{
    DEBUG_ENGINE("Entered\n");

    if (!pMethod)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    EC_KEY_METHOD_set_sign(pMethod, eccx08_ecdsa_sign, eccx08_ecdsa_sign_setup, eccx08_ecdsa_sign_sig);

#if ATCA_OPENSSL_ENGINE_ENABLE_HW_VERIFY
    EC_KEY_METHOD_set_verify(pMethod, eccx08_ecdsa_do_verify);
#endif

    return ENGINE_OPENSSL_SUCCESS;
}

#endif

