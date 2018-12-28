#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "openvpn-plugin.h"
#include "openvpn-transport.h"
#include "obfs-test.h"

struct openvpn_transport_bind_vtab1 obfs_test_bind_vtab = { 0 };
struct openvpn_transport_socket_vtab1 obfs_test_socket_vtab = { 0 };

struct obfs_test_context
{
    struct openvpn_plugin_callbacks *global_vtab;
};

static void
free_context(struct obfs_test_context *context)
{
    if (!context)
    {
        return;
    }
    free(context);
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(int version, struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *out)
{
    struct obfs_test_context *context;

    context = (struct obfs_test_context *) calloc(1, sizeof(struct obfs_test_context));
    if (!context)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    context->global_vtab = args->callbacks;
    obfs_test_initialize_vtabs_platform();
    obfs_test_bind_vtab.parseargs = obfs_test_parseargs;
    obfs_test_bind_vtab.argerror = obfs_test_argerror;
    obfs_test_bind_vtab.freeargs = obfs_test_freeargs;

    out->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TRANSPORT);
    out->handle = (openvpn_plugin_handle_t *) context;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

err:
    free_context(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    free_context((struct obfs_test_context *) handle);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(int version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr)
{
    /* We don't ask for any bits that use this interface. */
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void *
openvpn_plugin_get_vtab_v1(int selector, size_t *size_out)
{
    switch (selector)
    {
        case OPENVPN_VTAB_TRANSPORT_BIND_V1:
            if (obfs_test_bind_vtab.bind == NULL)
            {
                return NULL;
            }
            *size_out = sizeof(struct openvpn_transport_bind_vtab1);
            return &obfs_test_bind_vtab;

        default:
            return NULL;
    }
}

void
obfs_test_log(struct obfs_test_context *ctx,
              openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, OBFS_TEST_PLUGIN_NAME, fmt, va);
    va_end(va);
}
