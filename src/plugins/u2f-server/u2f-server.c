#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "openvpn-plugin.h"

#define U2F_SERVER_PLUGIN_NAME "u2f-server"

struct u2f_server_context
{
    struct openvpn_plugin_callbacks *global_vtab;
};

static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

static void
u2f_server_log(struct u2f_server_context *ctx,
               openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, U2F_SERVER_PLUGIN_NAME, fmt, va);
    va_end(va);
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(int version,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct u2f_server_context *ctx =
        calloc(1, sizeof(struct u2f_server_context));
    if (!ctx)
        return OPENVPN_PLUGIN_FUNC_ERROR;
    ctx->global_vtab = args->callbacks;

    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    ret->handle = (openvpn_plugin_handle_t *)ctx;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, int type,
                       const char *argv[], const char *envp[])
{
    struct u2f_server_context *ctx =
        (struct u2f_server_context *)handle;
    if (type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    const char *username = get_env("username", envp);
    const char *password = get_env("password", envp);
    const char *common_name = get_env("common_name", envp);
    const char *acf = get_env("auth_control_file", envp);

    if (!username || !password)
    {
        u2f_server_log(ctx, PLOG_ERR,
                       "expected username/password in environment set");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    for (const char **e = envp; *e; e++)
    {
        u2f_server_log(ctx, PLOG_DEBUG,
                       "env: %s", *e);
    }

    /* Not actually relevant yet. But it will be. */
    if (!acf)
    {
        u2f_server_log(ctx, PLOG_ERR,
                       "can't do deferred auth with no auth_control_file!");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* The worst password test ever. */
    if (strcmp(username, password) == 0)
    {
        u2f_server_log(ctx, PLOG_NOTE,
                       "successful authentication for %s", username);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
    else
    {
        u2f_server_log(ctx, PLOG_NOTE,
                       "failed authentication for %s", username);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct u2f_server_context *ctx = (struct u2f_server_context *)handle;

    free(ctx);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle)
{
    /* Stub for now, but will be needed later to terminate subprocess. */
}
