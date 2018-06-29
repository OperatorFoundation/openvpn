/* PORTING: crypt_r is a GNU extension... */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <crypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

    /* If 'handle' is NULL, 'stat0' is invalid.  If 'handle' is
       non-null, 'stat0' contains to the original results of fstat on
       its file descriptor. Each time 'handle' is set, 'open_count'
       is incremented; this includes the first time.
     */
    FILE *handle;
    struct stat stat0;
    unsigned open_count;

    struct {
        unsigned open_count;
        long pos;
        bool pos_synced;
        bool eof;
    } scan;

    struct u2fdbt_Record last_record;
};

static int
reopen(struct u2fdbt_FileC *filec)
{
    if (filec->handle)
    {
        fclose(filec->handle);
    }

    int fd = open(filec->path_buf, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
    {
        return -1;
    }

    int err = fstat(fd, &filec->stat0);
    if (err)
    {
        goto bad;
    }

    filec->handle = fdopen(fd, "r");
    if (!filec->handle)
    {
        goto bad;
    }

    filec->open_count++;
    return 0;

bad:
    /* label */ (void)0;
    int saved_errno = errno;
    if (fd != -1)
    {
        close(fd);
    }
    errno = saved_errno;
    return -1;
}

static bool
seems_unchanged(const struct stat *old, const struct stat *new)
{
    return (old->st_dev == new->st_dev && old->st_ino == new->st_ino
            && old->st_mtime == new->st_mtime && old->st_size == new->st_size);
}

static int
check_reopen(struct u2fdbt_FileC *filec)
{
    if (filec->handle)
    {
        struct stat stat1;
        int err = stat(filec->path_buf, &stat1);
        if (err)
        {
            return -1;
        }

        if (seems_unchanged(&filec->stat0, &stat1))
        {
            return 0;
        }
    }
    
    return reopen(filec);
}

static void
destroy(struct u2fdbt_FileC *filec)
{
    memset(&filec->last_record, 0, sizeof(struct u2fdbt_Record));
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
    if (!filec->line_buf)
    {
        goto oom;
    }

    int err = reopen(filec);
    if (err)
    {
        goto badio;
    }

    return &filec->public;

badio:
oom:
    /* label */ (void)0;
    int saved_errno = errno;
    destroy(filec);
    free(filec);
    errno = saved_errno;
    return NULL;
}

/* File handle must be open. */
static char *
fetch_line(struct u2fdbt_FileC *filec)
{
    memset(&filec->last_record, 0, sizeof(filec->last_record));
    char *line = fgets(filec->line_buf, filec->line_cap, filec->handle);
    if (line)
    {
        size_t len = strlen(line);
        if (line[len-1] == '\n')
        {
            line[len-1] = '\0';
            len--;
        }

        filec->line_len = len;
        return line;
    }
    else
    {
        return NULL;
    }
}

static inline int
safe_store_int64_llong(int64_t *p, long long val)
{
#if INT64_MAX < LLONG_MAX
    if ((long long)INT64_MAX < val)
    {
        /* Out of range. */
        return -1;
    }
#endif
#if LLONG_MIN < INT64_MIN
    if (val < (long long)INT64_MIN)
    {
        /* Out of range. */
        return -1;
    }
#endif
    *p = val;
    return 0;
}

/* TODO: maybe export something like this? */
/* TODO: use strchrnul more in here? */
static int
parse_line(char *line, struct u2fdbt_Record *record)
{
    int saved_errno = errno;
    char *here = line;
    memset(record, 0, sizeof(struct u2fdbt_Record));

    /* Field 1: name */
    record->name = here;
    char *sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;
    }
    else
    {
        goto end;
    }

    /* Field 2: pw_digest */
    record->pw_digest = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
        here = sep+1;
    }
    else
    {
        goto end;
    }

    /* Field 3: pw_mtime */
    char *pw_mtime_str = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    errno = 0;
    long long pw_mtime_ll = strtoll(pw_mtime_str, &here, 10);
    if (*here != '\0' || errno != 0)
    {
        /* Bad parse. */
        errno = EINVAL;
        goto bad;
    }
    if (safe_store_int64_llong(&record->pw_mtime, pw_mtime_ll))
    {
        /* Out of range. */
        errno = ERANGE;
        goto bad;
    }
    if (!sep)
    {
        goto end;
    }
    here = sep+1;

    /* Field 4: record_mtime */
    char *record_mtime_str = here;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    errno = 0;
    long long record_mtime_ll = strtoll(record_mtime_str, &here, 10);
    if (*here != '\0' || errno != 0)
    {
        /* Bad parse. */
        errno = EINVAL;
        goto bad;
    }
    if (safe_store_int64_llong(&record->record_mtime, record_mtime_ll))
    {
        /* Out of range. */
        errno = ERANGE;
        goto bad;
    }
    if (!sep)
    {
        goto end;
    }
    here = sep+1;

    /* Field 5: flags */
    char *flags_str = here;
    char *unknown_flags_end = flags_str;
    sep = strchr(here, ':');
    if (sep)
    {
        *sep = '\0';
    }
    unsigned flags = 0;

    /* Copy known flags into flags bitmask; move unknown
       flags to beginning of flags part of string. */
    while (*here)
    {
        switch (*here)
        {
            /* TODO: these case labels are not being indented right? */
        case 'D':
            flags |= U2FDBT_FLAG_DISABLED;
            break;
        case 'K':
            flags |= U2FDBT_FLAG_HAVE_KEYS;
            break;
        case 'R':
            flags |= U2FDBT_FLAG_REQUIRED;
            break;
        case 'S':
            flags |= U2FDBT_FLAG_SELF_REGISTER;
            break;
        default:
            flags |= U2FDBT_FLAG_UNKNOWN;
            *(unknown_flags_end++) = *here;
            break;
        }

        here++;
    }

    /* The flags_str is now the unknown flags string, the known flags
       having been filtered out. */
    *unknown_flags_end = '\0';
    record->flags = flags;
    record->unknown_flags = flags_str;

    /* TODO: parse remaining properties. */
end:
    /* TODO: consistency-check record, decide what to do about returning
       inconsistent records, as well as what to do about malformed lines
       and whether that should be consistent? */
    errno = saved_errno;
    return 0;
bad:
    /* TODO: propagating all errno values out of here doesn't work so great
       for detecting what happened in callers */
    return -1;
}

int
u2fdbt_rewind(struct u2fdbt_File *file)
{
    /* Lazy rewind. The next call to u2fdbt_next will do the fseek
       as needed. */
    struct u2fdbt_FileC *filec = file->opaque;
    filec->scan.eof = false;
    filec->scan.pos = 0;
    filec->scan.pos_synced = false;
    return 0;
}

const struct u2fdbt_Record *
u2fdbt_next(struct u2fdbt_File *file)
{
    struct u2fdbt_FileC *filec = file->opaque;
    if (filec->scan.eof)
    {
        /* Already at EOF. */
        return NULL;
    }

    int err = check_reopen(filec);
    if (err)
    {
        return NULL;
    }

    if (filec->open_count != filec->scan.open_count)
    {
        /* The file was reopened between now and the last
           u2fdbt_next() call. */
        filec->scan.pos_synced = false;
        if (filec->scan.pos != 0)
        {
            /* We know we weren't returning EOF because we checked for
               that above. So we were in the middle of a scan, so
               return that it was interrupted and arrange so that next
               time we'll start from the beginning. */
            filec->scan.pos = 0;
            errno = ESTALE;
            return NULL;
        }
    }

    if (!filec->scan.pos_synced)
    {
        err = fseek(filec->handle, filec->scan.pos, SEEK_SET);
        if (err)
        {
            return NULL;
        }

        filec->scan.pos_synced = true;
    }

next_line:
    /* label */ (void)0;
    char *line = fetch_line(filec);
    if (!line)
    {
        if (feof(filec->handle))
        {
            filec->scan.eof = true;
        }

        /* Pass through errno if there was an I/O error in
           fetch_line. Otherwise, it remains unset,
           Unix-style. */
        return NULL;
    }

    err = parse_line(line, &filec->last_record);
    if (err)
    {
        /* Skip truly malformed lines. This isn't great, but it's a
           little more robust than the alternatives... */
        goto next_line;
    }

    return &filec->last_record;
}

const struct u2fdbt_Record *
u2fdbt_find(struct u2fdbt_File *file, const char *name)
{
    /* Names can't contain colons. */
    if (strchr(name, ':'))
    {
        errno = EINVAL;
        return NULL;
    }

    struct u2fdbt_FileC *filec = file->opaque;
    int err = check_reopen(filec);
    if (err)
    {
        return NULL;
    }

    filec->scan.pos_synced = false;
    err = fseek(filec->handle, 0, SEEK_SET);
    if (err)
    {
        return NULL;
    }

    size_t name_len = strlen(name);
    char *line;
    while ((line = fetch_line(filec))) {
        if (strncmp(line, name, name_len) == 0
            && (line[name_len] == ':' || line[name_len] == '\0'))
        {
            err = parse_line(line, &filec->last_record);
            if (err)
            {
                /* TODO: probably shouldn't propagate errno */
                return NULL;
            }
            else
            {
                /* Found it. Make sure our original condition was
                   okay. Note that if the name contained a colon,
                   we already caught this above. */
                assert(!strcmp(filec->last_record.name, name));
                return &filec->last_record;
            }
        }
    }

    if (!ferror(filec->handle))
    {
        /* No I/O error, there just weren't any more lines.
           So, the name wasn't found. TODO: this error reporting
           though... */
        errno = ENOENT;
    }
    return NULL;
}

void
u2fdbt_close(struct u2fdbt_File *file)
{
    struct u2fdbt_FileC *filec = file->opaque;
    destroy(filec);
    free(filec);
}

bool
u2fdbt_digest_accepts_password(const char *digest, const char *password)
{
    if (digest[0] == '-' && digest[1] == '\0')
    {
        /* Top accepts all passwords. */
        return true;
    }
    else if (digest[0] == '*' && digest[1] == '\0')
    {
        /* Bottom never accepts any passwords. */
        return false;
    }
    else if (digest[0] == '$' && '0' <= digest[1] && digest[1] <= '9')
    {
        /* PORTING: crypt_r is a GNU extension, but... */
        struct crypt_data crypt_locals = { .initialized = 0 };
        char *result = crypt_r(password, digest, &crypt_locals);
        size_t expected_len = strlen(digest);
        /* TODO: memcmp_consttime... */
        /* return strlen(result) == expected_len && !memcmp_consttime(result, digest, expected_len); */
        return strcmp(result, digest) == 0;
    }
    else
    {
        errno = ERANGE;
        return false;
    }
}
