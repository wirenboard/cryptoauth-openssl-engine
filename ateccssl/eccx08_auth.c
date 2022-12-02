#include "eccx08_engine.h"
#include "eccx08_engine_internal.h"

#include "basic/atca_basic.h"
#include "host/atca_host.h"

#include <stdio.h>

#define PASSWD_SALT "atecc-salt123"
#define MAX_PASSWORDS 4

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

static int make_key_from_password(const char *password, uint8_t key[ATCA_KEY_SIZE])
{
    uint8_t buffer[MAX_PASSWD_LEN + sizeof (PASSWD_SALT) + 2];

    strcpy((char *) buffer, password);
    strcpy((char *) buffer + strlen(password), PASSWD_SALT);

    if (atcac_sw_sha2_256((const uint8_t *) buffer, strlen((char *) buffer), key) != 0) {
        return 0;
    }

    return 1;
}

static ATCA_STATUS do_atecc_auth(const char *passwd, uint8_t slot_id)
{
    /* make a key from password */
    uint8_t key[ATCA_KEY_SIZE];
    if (!make_key_from_password(passwd, key)) {
        return 0;
    }

    /* generate MAC of specific message */
    uint8_t sn[9];
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t other_data[12] = { 0 };
    uint8_t resp[32];
    ATCA_STATUS status;

    do {
        status = atcab_read_serial_number(sn);
        if (status != ATCA_SUCCESS) {
            eprintf("Command atcab_read_serial_number is failed with status 0x%x\n",
                    status);
            break;
        }

        status = atcab_nonce_rand(num_in, rand_out);
        if (status != ATCA_SUCCESS) {
            eprintf("Command atcab_nonce_rand is failed with status 0x%x\n",
                    status);
            break;
        }

        struct atca_temp_key temp_key;
        memset(&temp_key, 0, sizeof (temp_key));

        struct atca_nonce_in_out nonce_params = {
            .mode = NONCE_MODE_SEED_UPDATE,
            .zero = 0,
            .num_in = num_in,
            .rand_out = rand_out,
            .temp_key = &temp_key,
        };
        status = atcah_nonce(&nonce_params);
        if (status != ATCA_SUCCESS) {
            eprintf("Command atcah_nonce is failed with status 0x%x\n", status);
            break;
        }

        struct atca_check_mac_in_out check_mac = {
            .mode = 1,
            .key_id = slot_id,
            .sn = sn,
            .client_chal = NULL,
            .client_resp = resp,
            .other_data = other_data,
            .otp = NULL,
            .slot_key = key,
            .target_key = NULL,
            .temp_key = &temp_key,
        };
        status = atcah_check_mac(&check_mac);
        if (status != ATCA_SUCCESS) {
            eprintf("Command atcah_check_mac is failed with status 0x%x\n", status);
            break;
        }

        /* check MAC */
        status = atcab_checkmac(1, slot_id, NULL, resp, other_data);
        if (status == ATCA_CHECKMAC_VERIFY_FAILED) {
            eprintf("Authentication failure\n");
            break;
        }
        if (status != ATCA_SUCCESS) {
            eprintf("Command atcab_checkmac is failed with status 0x%x\n",
                    status);
            break;
        }
    } while (0);

    return status;
}

int eccx08_cbdata_to_password(void *callback_data, eccx08_engine_key_password_t *password)
{
    /* try to dereference callback data as string */
    /* assume callback_data == NULL as no pass */
    if (callback_data == NULL)
        return 0;

    const char *cb_pass = *((const char **) callback_data);

    if ((cb_pass == NULL) || (sscanf(cb_pass, "%02hu:%s", &password->auth_slot, password->password) != 2)) {
        return 0;
    } else {
        DEBUG_ENGINE("Raw password: %s\n", cb_pass);
        return 1;
    }
}

ATCA_STATUS eccx08_auth_password(const eccx08_engine_key_password_t *password)
{
    DEBUG_ENGINE("Entered\n");
    DEBUG_ENGINE("Slot: %hu, password: %s\n", password->auth_slot, password->password);
    return do_atecc_auth(password->password, password->auth_slot);
}

/** Password storage is a bad idea but should work */
static eccx08_engine_key_password_t __passwords[MAX_PASSWORDS];
static uint8_t current_id = 0;

eccx08_engine_key_password_t *eccx08_get_password(uint8_t id)
{
    if (id >= MAX_PASSWORDS) {
        return NULL;
    } else {
        return &__passwords[id];
    }
}

uint8_t eccx08_make_password(void)
{
    if (current_id < MAX_PASSWORDS) {
        uint8_t ret = current_id;
        current_id++;
        return ret;
    } else {
        DEBUG_ENGINE("Too many passwords!\n");
        return current_id;
    }
}

void eccx08_release_password(void)
{
    if (current_id > 0) {
        current_id--;
    }
}
