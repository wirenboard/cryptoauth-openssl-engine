/**
 * \file
 * \brief Human-readable engine errors in the standard OpenSSL error queue.
 *
 * On its own the framework reports every chip/bus/lock failure with the
 * same generic text ("failed loading private key", curl exit 58), which
 * collapses distinct root causes into one message. The engine therefore
 * registers its own error-string library and raises one error per
 * terminal session failure with the exact ATCA status decoded into
 * text. Always on - unlike the
 * ATECC_DIAG stderr tracing, this travels through the standard channel
 * (ERR_print_errors, curl verbose, client logs).
 */
#include "eccx08_engine.h"

#include <openssl/err.h>
#include <pthread.h>
#include <stdio.h>

#define ECCX08_R_SESSION_FAILED 100

static int err_lib = 0;

static ERR_STRING_DATA lib_name[] = {
    { 0, "ateccx08 engine" },
    { 0, NULL }
};

static ERR_STRING_DATA reasons[] = {
    { 0, "chip session failed" },
    { 0, NULL }
};

const char *eccx08_atca_status_name(int status)
{
    switch (status & 0xFF)
    {
    case 0xD0: return "wake failed";
    case 0xD9: return "RNG health test failed and latched (chip status 0x08)";
    case 0xE0: return "library state error";
    case 0xE1: return "unspecified chip failure";
    case 0xE5: return "CRC error in chip response (bus collision)";
    case 0xE6: return "chip response timed out mid-frame";
    case 0xE7: return "no response from chip";
    case 0xF0: return "communication with chip failed";
    case 0xF1: return "timeout waiting for chip response";
    default:   return "unknown ATCA status";
    }
}

static pthread_once_t err_load_once = PTHREAD_ONCE_INIT;

static void eccx08_err_do_load_strings(void)
{
    err_lib = ERR_get_next_error_library();
    lib_name[0].error = ERR_PACK(err_lib, 0, 0);
    reasons[0].error = ERR_PACK(err_lib, 0, ECCX08_R_SESSION_FAILED);
    ERR_load_strings(err_lib, lib_name);
    ERR_load_strings(err_lib, reasons);
}

void eccx08_err_load_strings(void)
{
    (void)pthread_once(&err_load_once, eccx08_err_do_load_strings);
}

void eccx08_raise_session_error(const char *op, int atca_status)
{
    char data[128];

    eccx08_err_load_strings();
    snprintf(data, sizeof(data), "op=%s, atca status 0x%02x: %s",
             op, atca_status & 0xFF, eccx08_atca_status_name(atca_status));
    ERR_put_error(err_lib, 0, ECCX08_R_SESSION_FAILED, __FILE__, __LINE__);
    ERR_add_error_data(1, data);
}
