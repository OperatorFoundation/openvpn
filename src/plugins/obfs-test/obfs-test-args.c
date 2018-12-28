#include "obfs-test.h"

openvpn_transport_args_t
obfs_test_parseargs(void *plugin_handle,
                    const char *const *argv, int argc)
{
    struct obfs_test_args *args = calloc(1, sizeof(struct obfs_test_args));
    if (!args)
    {
        return NULL;
    }

    if (argc < 2)
    {
        args->offset = 0;
    }
    else if (argc == 2)
    {
        char *end;
        long offset = strtol(argv[1], &end, 10);
        if (*end != '\0')
        {
            args->error = "offset must be a decimal number";
        }
        else if (!(0 <= offset && offset <= 42))
        {
            args->error = "offset must be between 0 and 42";
        }
        else
        {
            args->offset = (int) offset;
        }
    }
    else
    {
        args->error = "too many arguments";
    }

    return args;
}

const char *
obfs_test_argerror(openvpn_transport_args_t args_)
{
    if (!args_)
    {
        return "cannot allocate";
    }
    else
    {
        return ((struct obfs_test_args *) args_)->error;
    }
}

void
obfs_test_freeargs(openvpn_transport_args_t args_)
{
    free(args_);
    struct obfs_test_args *args = (struct obfs_test_args *) args_;
}
