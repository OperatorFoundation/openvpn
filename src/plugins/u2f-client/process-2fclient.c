#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <curl/curl.h>
#include <u2f-host/u2f-host.h>
#include "randombytes/randombytes.h"
#include "b64/b64.h"

#include "openvpn-plugin.h"
#include "comm-2fclient.h"

static const char program_name[] = "openvpn-2fclient";

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

static int
do_auth_request(u2fh_devs *devs, const char *packet, size_t len, struct msghdr *msg,
                const char **error, int register_first)
{
    int fd;
    const char *username;
    const char *password;
    const char *origin;
    unsigned char txidbytes[128];
    char *txid;
    long http_result;
    char *register_challenge;
    char *auth_challenge;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    CURL *curl=curl_easy_init();
    if(!curl)
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        *error = "Could not initialize libcurl";
        return AUTH_RESPONSE_ERROR;
    }

    if (comm_2fclient_parse_packet(packet, len, msg,
                                   "Fss", &fd, &username, &password, &origin))
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        *error = "malformed auth request";
        return AUTH_RESPONSE_ERROR;
    }

    /* The worst password check ever, redux. */
    int ok = (strcmp(username, password) == 0);

    randombytes(txidbytes, 128);
    txid=b64_encode(txidbytes, 128);

    /*
     * Endpoints for 2F server
     *
     * GET /auth/:id
     *   200, body: (JSON blob) - challenge being provided
     *   204 - no second factor, already okay
     *   303 → registration endpoint - in-band registration required
     *   ??? - out-of-band registration required
     *   (in 4xx because the client itself can't continue or retry)
     *   4xx - bad txn ID or other request problems
     *   5xx - broken
     *
     * POST /auth/:id, body: (JSON blob with response)
     *   202 - OK
     *   403 - bad response
     *   4xx - other request problems
     *   5xx - broken
     *
     * GET /register/:id
     *   200, body: (JSON blob) - challenge being provided
     *   204 - already registered, no challenge available
     *   4xx - bad txn ID or other request problems
     *   5xx - broken
     *
     * POST /register/:id, body:(JSON blob with response)
     *   202 - OK
     *   403 - bad response
     *   4xx - other request problems
     *   5xx - broken
     *
     */

    char url[1024];

    if(register_first)
    {
        sprintf(url, "https://%s/register/%s", origin, txid);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        CURLcode curl_result=curl_easy_perform(curl);
        if(curl_result!=CURLE_OK)
        {
            free(chunk.memory);
            curl_easy_cleanup(curl);
            *error = "Error from libcurl";
            return AUTH_RESPONSE_ERROR;
        }


        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
        switch(http_result)
        {
            case 200:
                /* 200, body: (JSON blob) - challenge being provided */
                // Convert to null-terminated string
                register_challenge=malloc(chunk.size+1);
                memcpy(register_challenge, chunk.memory, chunk.size);
                memset(register_challenge, 0, chunk.size);

                char response[2048];
                size_t response_len = sizeof (response);

                u2fh_rc result = u2fh_register2(devs, register_challenge, origin,
                                                    response, &response_len,
                                                    U2FH_REQUEST_USER_PRESENCE);
                free(register_challenge);

                if(result != U2FH_OK)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return AUTH_RESPONSE_IMMEDIATE_DENY;
                }

                // Convert to null-terminated string
                memset(response, 0, response_len);

                sprintf(url, "https://%s/register/%s", origin, txid);
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, response);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, response_len);

                curl_result=curl_easy_perform(curl);
                if(curl_result!=CURLE_OK)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    *error = "Error from libcurl";
                    return AUTH_RESPONSE_ERROR;
                }

                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
                switch(http_result)
                {
                    case 202:
                        /* 202 - OK */
                        break;
                    case 403:
                        /* 403 - bad response */
                        free(chunk.memory);
                        curl_easy_cleanup(curl);
                        return AUTH_RESPONSE_IMMEDIATE_DENY;
                    default:
                        free(chunk.memory);
                        curl_easy_cleanup(curl);
                        return AUTH_RESPONSE_ERROR;
                }
            case 204:
                /* 204 - no second factor, already okay */
                break;
            case 303:
                /* 303 → registration endpoint - in-band registration required */
                if(register_first)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    *error = "Stuck in a registration loop";
                    return AUTH_RESPONSE_ERROR;
                }
                else
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return do_auth_request(devs, packet, len, msg, error, 1);
                }
            default:
                free(chunk.memory);
                curl_easy_cleanup(curl);
                *error = "Bad result from libcurl fetching response";
                return AUTH_RESPONSE_ERROR;
        }
    }

    sprintf(url, "https://%s/auth/%s", origin, txid);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // Call curl_easy_setopt()?
    CURLcode curl_result=curl_easy_perform(curl);
    if(curl_result!=CURLE_OK)
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        *error = "Error from libcurl";
        return AUTH_RESPONSE_ERROR;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
    switch(http_result)
    {
        case 200:
            /* 200, body: (JSON blob) - challenge being provided */
            // Convert to null-terminated string
            auth_challenge=malloc(chunk.size+1);
            memcpy(auth_challenge, chunk.memory, chunk.size);
            memset(auth_challenge, 0, chunk.size);

            char response[2048];
            size_t response_len = sizeof (response);

            u2fh_rc result = u2fh_authenticate2(devs, auth_challenge, origin,
                                                response, &response_len,
                                                U2FH_REQUEST_USER_PRESENCE);
            free(auth_challenge);

            if(result != U2FH_OK)
            {
                curl_easy_cleanup(curl);
                return AUTH_RESPONSE_IMMEDIATE_DENY;
            }

            // Convert to null-terminated string
            memset(response, 0, response_len);

            sprintf(url, "https://%s/auth/%s", origin, txid);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_POST, 1);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, response);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, response_len);

            curl_result=curl_easy_perform(curl);
            if(curl_result!=CURLE_OK)
            {
                free(chunk.memory);
                curl_easy_cleanup(curl);
                *error = "Error from libcurl";
                return AUTH_RESPONSE_ERROR;
            }

            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
            switch(http_result)
            {
                case 202:
                    /* 202 - OK */
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return AUTH_RESPONSE_IMMEDIATE_PERMIT;
                case 403:
                    /* 403 - bad response */
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return AUTH_RESPONSE_IMMEDIATE_DENY;
                default:
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return AUTH_RESPONSE_ERROR;
            }
        case 204:
            /* 204 - no second factor, already okay */
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return AUTH_RESPONSE_IMMEDIATE_PERMIT;
            break;
        case 303:
            /* 303 → registration endpoint - in-band registration required */
            free(chunk.memory);
            curl_easy_cleanup(curl);
            do_auth_request(devs, packet, len, msg, error, 1);
            break;
        default:
            free(chunk.memory);
            curl_easy_cleanup(curl);
            *error = "Bad result from libcurl fetching response";
            return AUTH_RESPONSE_ERROR;
    }
}

static void
control_loop(int sock, u2fh_devs *devs)
{
    for (;;)
    {
        ssize_t len;
        union {
            char data[CMSG_SPACE(sizeof(int) * MAX_PACKET_FDS)];
            struct cmsghdr align;
        } ancillary;
        char packet[MAX_PACKET_BYTES];
        struct iovec iov = {
            .iov_base = packet,
            .iov_len = MAX_PACKET_BYTES
        };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = ancillary.data,
            .msg_controllen = sizeof(ancillary.data)
        };

        do {
            len = recvmsg(sock, &msg, 0);
        } while (len < 0 && errno == EAGAIN);

        if (len == 0)
        {
            comm_2fclient_send_error(sock, "bad zero-length packet");
            continue;
        }

        int result;
        const char *error;

        switch ((unsigned char)packet[0])
        {
            case OP_TERMINATE:
                comm_2fclient_send_packet(sock, OP_TERMINATE_ACK, "");
                /* return rather than break, to exit loop. */
                return;
            case OP_AUTH_REQUEST:
                result = do_auth_request(devs, packet, (size_t)len, &msg, &error, 0);
                switch (result)
                {
                    case AUTH_RESPONSE_IMMEDIATE_PERMIT:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_SUCCESS);
                        break;
                    case AUTH_RESPONSE_PENDING:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_DEFERRED);
                        break;
                    case AUTH_RESPONSE_IMMEDIATE_DENY:
                        comm_2fclient_send_packet(sock, OP_AUTH_RESPONSE, "b",
                                                  OPENVPN_PLUGIN_FUNC_ERROR);
                        break;
                    case AUTH_RESPONSE_ERROR:
                        comm_2fclient_send_error(sock, error);
                        break;
                    default:
                        abort();
                }
                break;
            default:
                comm_2fclient_send_error(sock, "unrecognized opcode");
                break;
        }

        /* TODO (defensive): close_spare_fds(&msg); */
    }
}

static int
parse_fd(const char *arg)
{
    errno = 0;
    unsigned long n = strtoul(arg, NULL, 10);
    if (errno)
        return -1;
#if ULONG_MAX > INT_MAX
    if (n > (unsigned long)INT_MAX)
        return -1;
#endif
    return (int)n;
}

static void
show_usage(void)
{
    fprintf(stderr, "Usage: %s -sSOCKET_FD\n", program_name);
    fputs("This program is normally only called by its attendant plugin.\n",
          stderr);
}

int
main(int argc, char *argv[])
{
    int control_socket = -1;
    int option;

    while ((option = getopt(argc, argv, ":s:h")) != -1)
    {
        switch (option)
        {
            case 's':
                control_socket = parse_fd(optarg);
                break;
            case 'h':
                show_usage();
                exit(0);
            case ':':
                fprintf(stderr, "%s: option -%c requires an argument\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            case '?':
                fprintf(stderr, "%s: unrecognized option -%c\n",
                        program_name, optopt);
                show_usage();
                exit(64);
            default:
                fprintf(stderr, "%s: error processing options\n",
                        program_name);
                show_usage();
                exit(64);
        }
    }

    if (control_socket == -1)
    {
        fprintf(stderr, "%s: no control socket found\n", program_name);
        show_usage();
        exit(66);
    }

    u2fh_initflags flags=U2FH_DEBUG;
    u2fh_rc result = u2fh_global_init(flags);
    if(result != U2FH_OK)
    {
      fprintf(stderr, "Error initializing u2fh library: %s", u2fh_strerror(result));
      u2fh_global_done();
      exit(67);
    }

    u2fh_devs *devs;
    result = u2fh_devs_init(&devs);
    if(result != U2FH_OK)
    {
      fprintf(stderr, "Error initializing u2fh device list: %s", u2fh_strerror(result));
      u2fh_global_done();
      exit(68);
    }

    result = u2fh_devs_discover(devs, NULL);
    if(result != U2FH_OK)
    {
      fprintf(stderr, "No U2F devices found: %s", u2fh_strerror(result));
      u2fh_devs_done(devs);
      u2fh_global_done();
      exit(69);
    }

    comm_2fclient_send_packet(control_socket, OP_INITIALIZED,
                              "b", BACKEND_PROTOCOL_VERSION);
    control_loop(control_socket, devs);
    u2fh_devs_done(devs);
    u2fh_global_done();
    return 0;
}
