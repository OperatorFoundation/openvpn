#include <stdio.h>
#include <stdbool.h>
#include "2fserver-http.h"
#include "2fserver-support.h"

static const char method_GET[] = "GET";
static const char method_POST[] = "POST";

static const char header_Content_Type[] = "Content-Type";
static const char ct_text_plain[] = "text/plain";
static const char ct_application_json[] = "application/json";

static const int rcode_bad_method = 405;
static struct MHD_Response *resp_bad_method;
static const int rcode_not_found = 404;
static struct MHD_Response *resp_not_found;
static const int rcode_no_challenge = 204;
static struct MHD_Response *resp_no_challenge;
static const int rcode_internal_error = 500;
static struct MHD_Response *resp_internal_error;

/* These must not contain %. */
static const char prefix_auth[] = "/auth/";
static const char prefix_register[] = "/register/";

static void
handle_mhd_panic(void *unused, const char *file, unsigned line,
                 const char *reason)
{
    (void)unused;
    /* TODO: maybe re-exec? */
    twofserver_eprintf("MHD panic: %s:%u: %s", file, line, reason);
    _exit(70);
}

static int
handle_request(void *unused, struct MHD_Connection *conn,
               const char *url, const char *method, const char *version,
               const char *data, size_t *data_size, void **state_cell)
{
    return MHD_queue_response(conn, rcode_no_challenge, resp_no_challenge);
}

void
twofserver_start_http(unsigned port)
{
    MHD_set_panic_func(&handle_mhd_panic, NULL);

    /* TODO: MHD_USE_SSL */
    unsigned flags = 0
        | MHD_USE_DUAL_STACK
        | MHD_USE_SELECT_INTERNALLY
        | MHD_USE_PEDANTIC_CHECKS
        | MHD_USE_POLL
        | MHD_USE_SUSPEND_RESUME;

    /* TODO:
         - less-hardcoded limits?
         - Move processing into main thread?
         - Do we need to use our own listening socket?
         - Need to add TLS certificate here.
         - TLS version/ciphers priority list.
    */
    struct MHD_OptionItem options[] = {
        { MHD_OPTION_CONNECTION_LIMIT, 500, NULL },
        { MHD_OPTION_CONNECTION_TIMEOUT, 5, NULL },
        { MHD_OPTION_PER_IP_CONNECTION_LIMIT, 2, NULL },
        { MHD_OPTION_END, 0, NULL }
    };

    struct MHD_Daemon *mhd =
        MHD_start_daemon(flags, port,
                         NULL, NULL, /* no access policy callback */
                         &handle_request, NULL,
                         MHD_OPTION_ARRAY, options,
                         MHD_OPTION_END);
    /* TODO: check result */

    /* TODO: check return codes */
    static const char str_bad_method[] = "bad method\n";
    resp_bad_method = MHD_create_response_from_buffer(
        sizeof(str_bad_method)-1, (void *)str_bad_method, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_bad_method, header_Content_Type, ct_text_plain);

    static const char str_not_found[] = "not found\n";
    resp_not_found = MHD_create_response_from_buffer(
        sizeof(str_not_found)-1, (void *)str_not_found, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_not_found, header_Content_Type, ct_text_plain);

    /* Must have zero-length content because HTTP code 204 implies that. */
    resp_no_challenge = MHD_create_response_from_buffer(
        0, (void *)"", MHD_RESPMEM_PERSISTENT);

    static const char str_internal_error[] = "internal error\n";
    resp_internal_error = MHD_create_response_from_buffer(
        sizeof(str_internal_error)-1, (void *)str_internal_error, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_internal_error, header_Content_Type, ct_text_plain);
}
