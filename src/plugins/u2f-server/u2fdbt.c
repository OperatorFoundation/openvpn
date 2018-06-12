#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "u2fdbt.h"

struct u2fdbt_Update {
    FILE *new;
};

struct u2fdbt_FileC {
    struct u2fdbt_File public;

    char *path_buf;
    size_t path_len, path_cap;

    char *line_buf;
    size_t line_len, line_cap;

    FILE *handle;
    /*
    dev_t dev;
    ino_t ino;
    */

    struct u2fdbt_Record *last_record;
};

static void
destroy(u2fdbt_FileC *filec)
{
    filec->last_record = NULL;
    free(filec->path_buf);
    filec->path_buf = NULL;
    free(filec->line_buf);
    filec->line_buf = NULL;
    if (filec->handle)
    {
        fclose(filec->handle);
        filec->handle = NULL;
    }
}

struct u2fdbt_File *
u2fdbt_open(const char *path)
{
    struct u2fdbt_FileC *filec = calloc(1, sizeof(struct u2fdbt_FileC));
    if (!filec)
    {
        return NULL;
    }

    filec->public.opaque = filec;

    /* One for optional trailing punctuation (used during updates), one
       for the null terminator. */
    filec->path_len = strlen(path);
    filec->path_cap = filec->path_len + 2;
    filec->path_buf = malloc(filec->path_cap);
    if (!filec->path_buf)
    {
        goto oom;
    }

    memcpy(filec->path_buf, path, filec->path_len);
    filec->path_buf[filec->path_len] = '\0';
    filec->path_buf[filec->path_len+1] = '\0';

    filec->line_len = 0;
    filec->line_cap = 4096;     /* TODO: doc/move */
    filec->line_buf = malloc(filec->line_cap);

    /* TODO: capture cwd if needed, do stat stuff */
    filec->handle = fopen(filec->path_buf, "r");
    if (!filec->handle)
    {
        goto badio;
    }

oom:
badio:
    int saved_errno = errno;
    destroy(filec);
    free(filec);
    errno = saved_errno;
    return NULL;
}
