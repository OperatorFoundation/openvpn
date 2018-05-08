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
                const char **error)
{
    int fd;
    const char *username;
    const char *password;
    const char *origin;
    unsigned char txidbytes[128];
    char *txid;

    if (comm_2fclient_parse_packet(packet, len, msg,
                                   "Fss", &fd, &username, &password, &origin))
    {
        *error = "malformed auth request";
        return AUTH_RESPONSE_ERROR;
    }

    /* The worst password check ever, redux. */
    int ok = (strcmp(username, password) == 0);

    randombytes(txidbytes, 128);
    txid=b64_encode(txidbytes, 128);

    CURL *curl=curl_easy_init();
    if(!curl)
    {
      curl_easy_cleanup(curl);
      *error = "Could not initialize libcurl";
      return AUTH_RESPONSE_ERROR;
    }

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    char url[1024];
    sprintf(url, "https://%s/wsapi/u2f/sign?username=%s:%s&password=%s", origin, username, txid, password);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    // Call curl_easy_setopt()?
    CURLcode curl_result=curl_easy_perform(curl);
    if(curl_result != CURLE_OK)
    {
      free(chunk.memory);
      curl_easy_cleanup(curl);
      *error = "Bad result from libcurl fetching response";
      return AUTH_RESPONSE_ERROR;
    }

    // Convert to null-terminated string
    char *challenge=malloc(chunk.size+1);
    memcpy(challenge, chunk.memory, chunk.size);
    memset(challenge, 0, chunk.size);
    free(chunk.memory);

    char response[2048];
    size_t response_len = sizeof (response);

    u2fh_rc result = u2fh_authenticate2(devs, challenge, origin,
             response, &response_len,
             U2FH_REQUEST_USER_PRESENCE);
    free(challenge);

    if(result != U2FH_OK)
    {
      curl_easy_cleanup(curl);
      return AUTH_RESPONSE_IMMEDIATE_DENY;
    }

    // Convert to null-terminated string
    memset(response, 0, response_len);

    sprintf(url, "https://%s/wsapi/u2f/verify?username=%s:%s&password=%s&data=%s", origin, username, txid, password, response);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_result=curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if(curl_result == CURLE_OK)
    {
      return AUTH_RESPONSE_IMMEDIATE_PERMIT;
    }
    else
    {
      return AUTH_RESPONSE_IMMEDIATE_DENY;
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
                result = do_auth_request(devs, packet, (size_t)len, &msg, &error);
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
