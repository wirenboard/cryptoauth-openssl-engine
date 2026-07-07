/**
 * \brief OpenSSL ENGINE - Main (bind/management interface) entry point
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
 *     Microchip integrated circuit.
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

/* Constants used when creating the ENGINE */
static const char * const engine_eccx08_id = ECCX08_ENGINE_ID;
static const char * const engine_eccx08_name = ECCX08_ENGINE_NAME;
/* Name of the shared-memory mutex region that serializes chip access
 * across every process on the system: engine loaders (openssl, curl,
 * nginx) and the direct cryptoauthlib users (wb tools and services).
 * The name is a frozen protocol constant shared by all of them: every
 * binary must use this exact value to meet the others on the same
 * region. Do NOT derive it from ECCX08_ENGINE_VERSION: bumping
 * the version would silently split chip users into two populations
 * that no longer exclude each other. */
static const char * const engine_eccx08_mutex_name = "ateccx08_01.00.10";

static ATCAIfaceCfg *ifacecfg = NULL;

static ENGINE *this_engine = NULL;

ENGINE *eccx08_engine(void)
{
    return this_engine;
}

/* Global Engine Configuration Structure */
eccx08_engine_config_t eccx08_engine_config;

/* Manage a global lock with locked state (1 - Ours, 0 - Not Ours) */
struct {
    void* handle;
    int state;
} global_lock = { NULL, 0 };

/* Set when the mutex was recovered from a dead owner (EOWNERDEAD): the chip
   was abandoned mid-session and must be resynchronized before use. */
static int global_lock_recovered = 0;

/** \brief Lock the global mutex */
ATCA_STATUS eccx08_global_lock(void)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    if (!global_lock.handle)
    {
        if (ATCA_SUCCESS != (status = hal_os_create_mutex(&global_lock.handle, engine_eccx08_mutex_name)))
        {
            return status;
        }
        global_lock.state = 0;
    }

    if (!global_lock.state)
    {
            DEBUG_ENGINE("About to lock mutex in global_lock\n");
        status = hal_os_lock_mutex(global_lock.handle);
        if (ATCA_FUNC_FAIL == status)
        {
            /* EOWNERDEAD: the mutex WAS obtained, but its previous owner
               died mid-session, so the chip state is unknown and possibly
               latched. The former blind 1.5 s delay assumed the chip
               watchdog would park it, but the watchdog does not run while
               the chip is idle-parked. Flag it instead;
               atcab_init_safe() resynchronizes the chip once the device
               interface is up. */
            global_lock_recovered = 1;
            status = ATCA_SUCCESS;
        }

        if (ATCA_SUCCESS == status)
        {
            global_lock.state = 1;
        }
    }

    return status;
}

/** \brief Unlock the global mutex */
ATCA_STATUS eccx08_global_unlock(void)
{
    ATCA_STATUS status = hal_os_unlock_mutex(global_lock.handle);

    if (ATCA_SUCCESS == status)
    {
        global_lock.state = 0;
    }

    return status;
}

/** \brief Thin abstraction on atcab_init that incorporates a global locking mechanism*/
ATCA_STATUS atcab_init_safe(ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status = eccx08_global_lock();

    if (ATCA_SUCCESS != status)
    {
        DIAG_ENGINE("event=session_fail op=lock status=0x%02x", status);
        eccx08_raise_session_error("lock", status);
        return status;
    }

    /* NB: every error path below must release the mutex - a lock left
       held until process exit gives the next client a spurious
       EOWNERDEAD plus a chip in an unknown state. */
    if (ifacecfg != NULL)
    {
        DIAG_ENGINE("event=session_fail op=init status=0x%02x", ATCA_FUNC_FAIL);
        (void)eccx08_global_unlock();
        return ATCA_FUNC_FAIL;
    }

    ifacecfg = (ATCAIfaceCfg *) malloc(sizeof (ATCAIfaceCfg));
    if (!ifacecfg)
    {
        DIAG_ENGINE("event=session_fail op=init status=0x%02x", ATCA_FUNC_FAIL);
        (void)eccx08_global_unlock();
        return ATCA_FUNC_FAIL;
    }

    memcpy(ifacecfg, cfg, sizeof (ATCAIfaceCfg));

    status = atcab_init(ifacecfg);
    if (ATCA_SUCCESS != status)
    {
        DIAG_ENGINE("event=session_fail op=init status=0x%02x", status);
        eccx08_raise_session_error("init", status);
        free(ifacecfg);
        ifacecfg = NULL;
        (void)eccx08_global_unlock();
        return status;
    }

    if (global_lock_recovered)
    {
        /* The previous lock owner died mid-session: park the chip through
           a best-effort wake+sleep so this session starts from a known
           state instead of riding an abandoned (possibly latched) one. */
        DIAG_ENGINE("event=eownerdead_resync");
        (void)atcab_wakeup();
        (void)atcab_sleep();
        global_lock_recovered = 0;
    }

    return ATCA_SUCCESS;
}

/** \brief Thin abstraction on atcab_release that incorporates a global locking mechanism*/
ATCA_STATUS atcab_release_safe(void)
{
    ATCA_STATUS status = eccx08_global_lock();

    if (ATCA_SUCCESS != status)
    {
        return status;
    }

    if (ifacecfg == NULL)
    {
        (void)eccx08_global_unlock();
        return ATCA_FUNC_FAIL;
    }

    /* Park the chip with SLEEP at the end of every session.
     *
     * Every command ends with _atcab_exit() -> atcab_idle(); idle both
     * suspends the chip watchdog and preserves any latched fault state
     * (health-test 0x08 latch or "corrupted idle") indefinitely.  A real
     * Sleep wipes those states, so ending every engine session with Sleep
     * both prevents latches from persisting and cures a chip corrupted by
     * a concurrent unlocked client.
     *
     * The wake is NOT optional: an idle-parked chip ignores all SCL
     * activity and accepts flags only while awake (DS 7.1.1/7.2), so a
     * bare sleep flag would never reach it - it must be woken first.
     *
     * Both calls are still best-effort by design: in the "corrupted idle"
     * state the wake response read fails, but the subsequent sleep flag
     * write is anomalously ACKed by the chip and cures it; on an
     * already-awake chip the extra wake is harmless.  TempKey loss from
     * Sleep is irrelevant here: the session is over. */
    {
        ATCA_STATUS wake_status = atcab_wakeup();
        ATCA_STATUS park_status = atcab_sleep();

        /* A park that did not land cleanly is the genesis of the
           "corrupted idle" latch - make it observable. */
        if (ATCA_SUCCESS != wake_status || ATCA_SUCCESS != park_status)
        {
            DIAG_ENGINE("event=park_anomaly wake=0x%02x sleep=0x%02x",
                        wake_status, park_status);
        }
    }

    status = atcab_release();

    free(ifacecfg);
    ifacecfg = NULL;

    (void)eccx08_global_unlock();

    return status;
}

/** \brief Run atcab_init_safe from keyinfo structure */
ATCA_STATUS atcab_init_from_privkey_safe(const EC_KEY *key, uint8_t *slot_num)
{
    ATCA_STATUS status = ATCA_FUNC_FAIL;
    ATCAIfaceCfg cfgbuffer;
    union {
        eccx08_engine_key_t *keyinfo;
        unsigned char *bnbuffer;
    } u;
    u.bnbuffer = NULL;

    do {
        const BIGNUM* bn = EC_KEY_get0_private_key(key);
        if (!bn)
        {
            DEBUG_ENGINE("failed to get private part of EC key\n");
            break;
        }

        u.bnbuffer = (unsigned char *) malloc(BN_num_bytes(bn));

        if (!u.bnbuffer) {
            DEBUG_ENGINE("failed to allocate space for private key\n");
            return status;
        }

        if (!BN_bn2bin(bn, u.bnbuffer))
        {
            DEBUG_ENGINE("can't convert BN to key info\n");
            break;
        }

        if (!eccx08_get_iface_cfg(&cfgbuffer, u.keyinfo))
        {
            DEBUG_ENGINE("failed to get ifacecfg from keyinfo\n");
            break;
        }

        status = atcab_init_safe(&cfgbuffer);
        if (status != ATCA_SUCCESS)
        {
            DEBUG_ENGINE("atcab_init_safe failed with result 0x%02x\n", status);
            break;
        }

        *slot_num = u.keyinfo->slot_num;

    } while (0);

    if (u.bnbuffer) {
         free(u.bnbuffer);
    }

    return status;
}

/**
*  \brief Deinitialize the engine.
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return For success return 1
*/
static int eccx08_destroy(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

    if (hal_os_destroy_mutex(global_lock.handle))
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    global_lock.state = 0;
    global_lock.handle = NULL;

    DEBUG_ENGINE("Finished\n");

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*  \brief Initialization the ateccx08 engine.
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return For success return 1
*/
static int eccx08_init(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

    /* Marker for test harnesses: confirms the DIAG channel of this
       process is enabled and reaches stderr, so an absence of later DIAG
       events means "nothing happened" rather than "diagnostics off". */
    DIAG_ENGINE("event=engine_ready");

    eccx08_err_load_strings();

    if (!global_lock.handle)
    {
        if (hal_os_create_mutex(&global_lock.handle, engine_eccx08_mutex_name))
        {
            return ENGINE_OPENSSL_FAILURE;
        }
        global_lock.state = 0;
    }

    /* Perform basic library initialization */
    eccx08_platform_init();
#if ATCA_OPENSSL_ENGINE_ENABLE_CERTS
    eccx08_cert_init();
#endif
#if ATCA_OPENSSL_ENGINE_ENABLE_RAND
    eccx08_rand_init();
#endif

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*
* \brief Complete all functions before deinitialization of the ateccx08 engine
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \return 1 for success
*/
static int eccx08_finish(ENGINE *e)
{
    DEBUG_ENGINE("Entered\n");

#if ATCA_OPENSSL_ENGINE_ENABLE_CERTS
    eccx08_cert_cleanup();
#endif

#if ATCA_OPENSSL_OLD_API
    eccx08_ecdsa_cleanup();
    eccx08_pkey_meth_cleanup();
#else
    eccx08_ec_cleanup();
#endif

    return ENGINE_OPENSSL_SUCCESS;
}

/**
*  \brief Binds ATECCx08 Engine to OpenSSL crypto API
*
* \param[in] e A pointer to Engine structure that completely describes the engine
* \param[in] id String to identify the Engine implementation (e.g. "ateccx08")
* \return For success return 1
*/
static int bind_helper(ENGINE *e, const char *id)
{
    int rv = ENGINE_OPENSSL_FAILURE;

    DEBUG_ENGINE("Entered\n");
    if (id && (strcmp(id, engine_eccx08_id) != 0)) {
        return ENGINE_OPENSSL_FAILURE;
    }

    do
    {
        /* Register Engine Basics */
        if (!ENGINE_set_id(e, engine_eccx08_id))
            break;

        if (!ENGINE_set_name(e, engine_eccx08_name))
            break;

        if (!ENGINE_set_init_function(e, eccx08_init))
            break;

        if (!ENGINE_set_destroy_function(e, eccx08_destroy))
            break;

        if (!ENGINE_set_finish_function(e, eccx08_finish))
            break;

        if (!ENGINE_set_ctrl_function(e, eccx08_cmd_ctrl))
            break;

        if (!ENGINE_set_cmd_defns(e, eccx08_cmd_defns))
            break;

        /* Hardware Support Interfaces */
#if ATCA_OPENSSL_ENGINE_ENABLE_RAND
        if (!ENGINE_set_RAND(e, &eccx08_rand))
            break;
#endif

#if ATCA_OPENSSL_ENGINE_ENABLE_SHA256
        if (!ENGINE_set_digests(e, eccx08_sha256_selector))
            break;
#endif

#if ATCA_OPENSSL_ENGINE_ENABLE_CERTS
        if (!ENGINE_set_load_ssl_client_cert_function(e, eccx08_cert_load_client))
            break;
#endif

#if ATCA_OPENSSL_ENGINE_ENABLE_CIPHERS
        if (!eccx08_cipher_init())
            break;
        if (!ENGINE_set_ciphers(e, ENGINE_CIPHERS_PTR f))
            break;
#endif

#if ATCA_OPENSSL_OLD_API && ATCA_OPENSSL_ENGINE_ECDH
        /* Use the 1.0.2x Defined API for ECDH */
        {
            ECDH_METHOD * ecdh_method_ptr = NULL;
            if (!eccx08_ecdh_init(&ecdh_method_ptr))
                break;
            if (!ENGINE_set_ECDH(e, ecdh_method_ptr))
                break;
        }
#endif

#if ATCA_OPENSSL_OLD_API && ATCA_OPENSSL_ENGINE_ECDSA
        /* Use the 1.0.2x Defined API for ECDSA */
        {
            ECDSA_METHOD * ecdsa_meth_ptr = NULL;
            if (!eccx08_ecdsa_init(&ecdsa_meth_ptr))
                break;
            if (!ENGINE_set_ECDSA(e, ecdsa_meth_ptr))
                break;
        }
#endif

#if !ATCA_OPENSSL_OLD_API && (ATCA_OPENSSL_ENGINE_ECDH || ATCA_OPENSSL_ENGINE_ECDSA)
        /* Use the 1.1.x Defined API for ECDSA and ECDH */
        {
            EC_KEY_METHOD * ec_meth_ptr = NULL;
            if (!eccx08_ec_init(&ec_meth_ptr))
                break;
            if (!ENGINE_set_EC(e, ec_meth_ptr))
                break;
        }
#endif

        if (!ENGINE_set_load_pubkey_function(e, eccx08_load_pubkey))
            break;

        if (!ENGINE_set_load_privkey_function(e, eccx08_load_privkey))
            break;

#if ATCA_OPENSSL_ENGINE_REGISTER_PKEY
        if (!eccx08_pkey_meth_init())
            break;
        if (!ENGINE_set_pkey_meths(e, eccx08_pmeth_selector))
            break;
#endif

        rv = ENGINE_OPENSSL_SUCCESS;
    } while (0);

    if (rv)
    {
        DEBUG_ENGINE("Succeeded\n");
        this_engine = e;
    }
    else
    {
        DEBUG_ENGINE("FAILED, Error: %ld\n", ERR_peek_error());
    }

    return rv;
}

#ifdef ENGINE_DYNAMIC_SUPPORT
IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);
#endif

#ifndef ENGINE_DYNAMIC_SUPPORT
/**
 * \brief An engine entry point. As this is only ever called
 * once, there's no need for locking (indeed - the lock will
 * already be held by our caller!!!)
 */
static ENGINE* ENGINE_ateccx08(void)
{
    DEBUG_ENGINE("Entered\n");
    ENGINE *eng = ENGINE_new();

    if (!eng) {
        return NULL;
    }
    if (!bind_helper(eng, engine_eccx08_id)) {
        ENGINE_free(eng);
        return NULL;
    }

    return eng;
}

/**
 *  \brief Load ATECCx08 Engine
 */
static void ENGINE_load_ateccx08(void)
{
    DEBUG_ENGINE("Entered\n");
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = ENGINE_ateccx08();
    if (!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif
