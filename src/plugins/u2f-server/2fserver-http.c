#include <stdio.h>
#include <stdbool.h>
#include "2fserver-http.h"

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

static const char *
after_prefix(const char *string, const char *prefix, size_t prefix_len)
{
    if (prefix_len == 0)
        prefix_len = strlen(prefix);
    if (strncmp(string, prefix, prefix_len))
        return NULL;
    return string + prefix_len;
}

#define after_prefix_static(string, prefix) \
    after_prefix(string, prefix, sizeof(prefix)-1)

enum RequestState {
    REQUEST_SUSPENDED_CHALLENGE = 1
};

struct PendingRequest {
    twofserver_TxnId txn_id;
    enum RequestState state;
};

static int
request_auth_challenge(struct MHD_Connection *conn,
                       const char *path_suffix, void **state_cell)
{
    /* Authentication challenge is being requested. */
    twofserver_TxnId txn_id;

    if (!txn_id_from_path(&txn_id, path_suffix))
        return MHD_queue_response(conn, rcode_not_found,
                                  resp_not_found);

    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(&txn_id);
    if (record)
    {
        /* Operation already pending. */
        enum ChallengeResultType chaltype;
        const char *chaltext =
            twofserver_challenge_for_auth(record, &chaltype);
        twofserver_unlock_pending_auth(record);
        record = NULL;

        int rcode = 0;
        struct MHD_Response *resp = NULL;
        bool free_resp = false;
        const char *redirect;

        /* TODO: switch indentation is weird for no good reason */
        switch (chaltype)
        {
            case TWOFSERVER_CHALLENGE_PROVIDED:
                rcode = rcode_ok;
                resp = MHD_create_response_from_buffer(
                    strlen(chaltext), chaltext, MHD_RESPMEM_MUST_FREE);
                free_resp = true;
                break;
    
            case TWOFSERVER_CHALLENGE_UNNECESSARY:
                rcode = rcode_no_challenge;
                resp = resp_no_challenge;
                break;
    
            case TWOFSERVER_CHALLENGE_REGISTRATION_REQUIRED:
                redirect = format_path("%s%I", prefix_register, &txn_id);
                rcode = 303;
                resp = MHD_create_response_from_buffer(
                    0, "", MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(resp, header_Content_Type, ct_text_plain);
                MHD_add_response_header(resp, header_Location, redirect);
                free(redirect);
                redirect = NULL;
                free_resp = true;
                break;
    
            default:
                /* Whoa, that's wrong. */
                rcode = rcode_internal_error;
                resp = resp_internal_error;
                break;
        }

        int ok = MHD_queue_response(conn, rcode, resp);
        if (free_resp)
        {
            MHD_destroy_response(resp);
            resp = NULL;
        }
        return ok;
    }
    else
    {
        /* This request arrived first, so we have to wait to
           respond to it until the OpenVPN auth succeeds. */
        struct PendingRequest *suspended =
            calloc(1, sizeof(struct PendingRequest));
        /* TODO: log OOM */
        if (!suspended)
            return MHD_NO;
        suspended->state = REQUEST_SUSPENDED_CHALLENGE;
        twofserver_copy_txn_id(&suspended->txn_id, &txn_id);
        *state_cell = suspended;

        struct twofserver_PendingAuth *record =
            twofserver_new_pending_auth(&txn_id);
        record->challenge_conn = conn;
        twofserver_queue_pending_auth(record);

        /* No response yet. */
        MHD_suspend_connection(conn);
        /* TODO: check return of MHD_suspend_connection */
        return MHD_YES;
    }
}

static int
post_auth_attempt(struct MHD_Connection *conn,
                  const char *path_suffix,
                  const char *data, size_t *data_size,
                  void **state_cell)
{
    /* Response to authentication challenge is being posted. */

    twofserver_TxnId txn_id;
    if (!txn_id_from_path(&txn_id, path_suffix))
        return MHD_queue_response(conn, rcode_not_found,
                                  resp_not_found);

    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(&txn_id);
    if (!record)
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);

    twofserver_fail_pending_auth(record);
}

static int
get_reg_challenge(struct MHD_Connection *conn,
                  const char *path_suffix, void **state_cell)
{
    /* Registration challenge is being requested. */

    twofserver_TxnId txn_id;
    if (!txn_id_from_path(&txn_id, tail))
        return MHD_queue_response(conn, rcode_not_found,
                                  resp_not_found);

    struct twofserver_PendingAuth *record =
        twofserver_lock_pending_auth(&txn_id);
    if (!record)
    {
        /* We should only get here after the user tried to request
           a challenge and got a redirect, so we don't auto-create
           new records when handling a registration per se. */
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);
    }

    const char *chaltext =
        twofserver_challenge_for_reg(record);
    twofserver_unlock_pending_auth(record);
    record = NULL;

    if (!chaltext)
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen(chaltext), chaltext, MHD_RESPMEM_MUST_FREE);
    chaltext = NULL;

    int ok = MHD_queue_response(conn, rcode_ok, resp);
    MHD_destroy_response(resp);
    return ok;
}

static int
handle_request(void *unused, struct MHD_Connection *conn,
               const char *url, const char *method, const char *version,
               const char *data, size_t *data_size, void **state_cell)
{
    const char *tail;

    if ((tail = after_prefix_static(url, prefix_auth)))
    {
        if (!strcmp(method, method_GET))
        {
            return get_auth_challenge(conn, tail, state_cell);
        }
        else if (!strcmp(method, method_POST))
        {
            return post_auth_attempt(conn, tail, data, data_size, state_cell);
        }
        else
        {
            return MHD_queue_response(conn, rcode_bad_method, resp_bad_method);
        }
    }
    else if ((tail = after_prefix_static(url, prefix_register)))
    {
        if (!strcmp(method, method_GET))
        {
            return get_reg_challenge(conn, tail, state_cell);
        }
        else if (!strcmp(method, method_POST))
        {
            return post_reg_attempt(conn, tail, data, data_size, state_cell);
        }
        else
        {
            return MHD_queue_response(conn, rcode_bad_method, resp_bad_method);
        }
    }
    else
    {
        return MHD_queue_response(conn, rcode_not_found, resp_not_found);
    }
}

void
twofserver_start_http(unsigned port)
{
    MHD_set_panic_func(&handle_mhd_panic, NULL);

    unsigned flags = MHD_USE_SSL
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
        sizeof(str_bad_method)-1, str_bad_method, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_bad_method, header_Content_Type, ct_text_plain);

    static const char str_not_found[] = "not found\n";
    resp_not_found = MHD_create_response_from_buffer(
        sizeof(str_not_found)-1, str_not_found, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_not_found, header_Content_Type, ct_text_plain);

    /* Must have zero-length content because HTTP code 204 implies that. */
    resp_no_challenge = MHD_create_response_from_buffer(
        "", 0, MHD_RESPMEM_PERSISTENT);

    static const char str_internal_error[] = "internal error\n";
    resp_internal_error = MHD_create_response_from_buffer(
        sizeof(str_internal_error)-1, str_internal_error, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp_internal_error, header_Content_Type, ct_text_plain);
}
