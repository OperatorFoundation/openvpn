#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "2fserver-model.h"

static struct twofserver_PendingAuth *the_record;
static pthread_mutex_t the_table_mutex = PTHREAD_MUTEX_INITIALIZER;

struct twofserver_PendingAuth *
twofserver_new_pending_auth(twofserver_TxnId id)
{
    int err;
    struct twofserver_PendingAuth *record =
        calloc(sizeof(struct twofserver_PendingAuth), 1);
    if (!record)
        return NULL;
    twofserver_txn_id_copy(&record->txn_id, &id);
    /* Everything else is either initialized to zero or is unset
       based on something else initialized to zero. */
    return record;
}

void
twofserver_queue_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(!record->locked);
    pthread_mutex_lock(&the_table_mutex);
    /* FIXME: leaks the previous record */
    the_record = record;
    pthread_mutex_unlock(&the_table_mutex);
}

void
twofserver_discard_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(!record->locked);
    free(record);
}

struct twofserver_PendingAuth *
twofserver_lock_pending_auth(twofserver_TxnId id)
{
    pthread_mutex_lock(&the_table_mutex);
    struct twofserver_PendingAuth *record = the_record;
    if (!record)
        goto eexist;
    if (twofserver_txn_id_cmp(&record->txn_id, &id))
        goto eexist;
    if (record->locked)
    {
        errno = EBUSY;
        goto bad;
    }
    record->locked = true;
    pthread_mutex_unlock(&the_table_mutex);
    return record;

  eexist:
    errno = EEXIST;
    /* fall through */
  bad:
    pthread_mutex_unlock(&the_table_mutex);
    return NULL;
}

void
twofserver_unlock_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(record->locked);
    pthread_mutex_lock(&the_table_mutex);
    record->locked = false;
    pthread_mutex_unlock(&the_table_mutex);
}

static void
destroy(struct twofserver_PendingAuth *record)
{
    assert(record->locked);
    pthread_mutex_lock(&the_table_mutex);
    assert(the_record == record);
    the_record = NULL;
    free(record);
    pthread_mutex_unlock(&the_table_mutex);
}

static void
write_acf(struct twofserver_PendingAuth *record, char ch)
{
    if (record->success1 && record->final_response_fd != -1)
    {
        record->final_response_char = ch;
        /* TODO: full_write? */
        write(record->final_response_fd, &ch, 1);
        close(record->final_response_fd);
        record->final_response_fd = -1;
    }
}

void
twofserver_pass_pending_auth(struct twofserver_PendingAuth *record)
{
    write_acf(record, '1');
    destroy(record);
}

void
twofserver_fail_pending_auth(struct twofserver_PendingAuth *record)
{
    write_acf(record, '0');
    destroy(record);
}

/* Returns -1 for chars that are not hex digits. */
static int
hex_ctoi(char ch)
{
    if ('0' <= ch && ch <= '9')
        return (int)ch - '0';
    else if ('a' <= ch && ch <= 'f')
        return 10 + ((int)ch - 'a');
    else if ('A' <= ch && ch <= 'F')
        return 10 + ((int)ch - 'A');
    else
        return -1;
}

int
twofserver_txn_id_parse(twofserver_TxnId *out, const char *in)
{
    char *dst = &out->bytes[0];
    if (strlen(in) != TWOFSERVER_TXN_ID_LEN * 2)
        return -1;

    for (int i = 0; i < TWOFSERVER_TXN_ID_LEN; i++)
    {
        /* byte < 0 iff either hex_ctoi returned a value < 0 */
        int byte = (hex_ctoi(in[i*2+0]) << 4) | hex_ctoi(in[i*2+1]);
        if (byte < 0)
            return -1;
        out->bytes[i] = byte;
    }

    return 0;
}
