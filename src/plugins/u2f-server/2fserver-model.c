#include <assert.h>
#include <errno.h>
#include <stdlib.h>
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
    twofserver_copy_txn_id(&record->txn_id, &id);
    /* locked is already initialized to 0. */
    return record;
}

void
twofserver_queue_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(!record->locked);
    the_record = record;
}

void
twofserver_free_pending_auth(struct twofserver_PendingAuth *record)
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
    if (twofserver_cmp_txn_id(&record->txn_id, &id))
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

void
twofserver_destroy_pending_auth(struct twofserver_PendingAuth *record)
{
    assert(record->locked);
    pthread_mutex_lock(&the_table_mutex);
    assert(the_record == record);
    the_record = NULL;
    free(record);
    pthread_mutex_unlock(&the_table_mutex);
}
