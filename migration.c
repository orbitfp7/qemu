/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "qemu/main-loop.h"
#include "migration/migration.h"
#include "monitor/monitor.h"
#include "migration/qemu-file.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "qemu/sockets.h"
#include "migration/block.h"
#include "migration/postcopy-ram.h"
#include "qemu/thread.h"
#include "qmp-commands.h"
#include "trace.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"

//#define DEBUG_MIGRATION

#ifdef DEBUG_MIGRATION
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "migration@%" PRId64 " " fmt "\n", \
                          qemu_clock_get_ms(QEMU_CLOCK_REALTIME), \
                          ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

enum MigrationPhase {
    MIG_STATE_ERROR = -1,
    MIG_STATE_NONE,
    MIG_STATE_SETUP,
    MIG_STATE_CANCELLING,
    MIG_STATE_CANCELLED,
    MIG_STATE_ACTIVE,
    MIG_STATE_POSTCOPY_ACTIVE,
    MIG_STATE_COMPLETED,
};

#define MAX_THROTTLE  (32 << 20)      /* Migration speed throttling */

/* Amount of time to allocate to each "chunk" of bandwidth-throttled
 * data. */
#define BUFFER_DELAY     100
#define XFER_LIMIT_RATIO (1000 / BUFFER_DELAY)

/* Migration XBZRLE default cache size */
#define DEFAULT_MIGRATE_CACHE_SIZE (64 * 1024 * 1024)

static NotifierList migration_state_notifiers =
    NOTIFIER_LIST_INITIALIZER(migration_state_notifiers);

/* When we add fault tolerance, we could have several
   migrations at once.  For now we don't need to add
   dynamic creation of migration */

/* For outgoing */
MigrationState *migrate_get_current(void)
{
    static MigrationState current_migration = {
        .state = MIG_STATE_NONE,
        .bandwidth_limit = MAX_THROTTLE,
        .xbzrle_cache_size = DEFAULT_MIGRATE_CACHE_SIZE,
        .mbps = -1,
    };

    return &current_migration;
}

/* For incoming */
static MigrationIncomingState *mis_current;

MigrationIncomingState *migration_incoming_get_current(void)
{
    return mis_current;
}

MigrationIncomingState *migration_incoming_state_init(QEMUFile* f)
{
    mis_current = g_malloc0(sizeof(MigrationIncomingState));
    mis_current->file = f;
    qemu_mutex_init(&mis_current->rp_mutex);

    return mis_current;
}

void migration_incoming_state_destroy(void)
{
    postcopy_pmi_destroy(mis_current);
    g_free(mis_current);
    mis_current = NULL;
}

/* Send a message on the return channel back to the source
 * of the migration.
 */
void migrate_send_rp_message(MigrationIncomingState *mis,
                             enum mig_rpcomm_cmd cmd,
                             uint16_t len, uint8_t *data)
{
    DPRINTF("migrate_send_rp_message: cmd=%d, len=%d\n", (int)cmd, len);
    qemu_mutex_lock(&mis->rp_mutex);
    qemu_put_be16(mis->return_path, (unsigned int)cmd);
    qemu_put_be16(mis->return_path, len);
    qemu_put_buffer(mis->return_path, data, len);
    qemu_fflush(mis->return_path);
    qemu_mutex_unlock(&mis->rp_mutex);
}

/*
 * Send a 'SHUT' message on the return channel with the given value
 * to indicate that we've finished with the RP.  None-0 value indicates
 * error.
 */
void migrate_send_rp_shut(MigrationIncomingState *mis,
                          uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RPCOMM_SHUT, 4, (uint8_t *)&buf);
}

/* Send an 'ACK' message on the return channel with the given value */
void migrate_send_rp_ack(MigrationIncomingState *mis,
                         uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RPCOMM_ACK, 4, (uint8_t *)&buf);
}

/* Request a range of pages from the source VM at the given
 * start address.
 *   rbname: Name of the RAMBlock to request the page in, if NULL it's the same
 *           as the last request (a name must have been given previously)
 *   Start: Address offset within the RB
 *   Len: Length in bytes required - must be a multiple of pagesize
 */
void migrate_send_rp_reqpages(MigrationIncomingState *mis, const char *rbname,
                              ram_addr_t start, ram_addr_t len)
{
    uint8_t bufc[16+1+255]; /* start (8 byte), len (8 byte), rbname upto 256 */
    uint64_t *buf64 = (uint64_t *)bufc;
    size_t msglen = 16; /* start + len */

    assert(!(len & 1));
    if (rbname) {
        int rbname_len = strlen(rbname);
        assert(rbname_len < 256);

        len |= 1; /* Flag to say we've got a name */
        bufc[msglen++] = rbname_len;
        memcpy(bufc + msglen, rbname, rbname_len);
        msglen += rbname_len;
    }

    buf64[0] = (uint64_t)start;
    buf64[0] = cpu_to_be64(buf64[0]);
    buf64[1] = (uint64_t)len;
    buf64[1] = cpu_to_be64(buf64[1]);
    migrate_send_rp_message(mis, MIG_RPCOMM_REQPAGES, msglen, bufc);
}

void qemu_start_incoming_migration(const char *uri, Error **errp)
{
    const char *p;

    if (strstart(uri, "tcp:", &p))
        tcp_start_incoming_migration(p, errp);
#ifdef CONFIG_RDMA
    else if (strstart(uri, "rdma:", &p))
        rdma_start_incoming_migration(p, errp);
#endif
#if !defined(WIN32)
    else if (strstart(uri, "exec:", &p))
        exec_start_incoming_migration(p, errp);
    else if (strstart(uri, "unix:", &p))
        unix_start_incoming_migration(p, errp);
    else if (strstart(uri, "fd:", &p))
        fd_start_incoming_migration(p, errp);
#endif
    else {
        error_setg(errp, "unknown migration protocol: %s", uri);
    }
}

static void process_incoming_migration_co(void *opaque)
{
    QEMUFile *f = opaque;
    Error *local_err = NULL;
    MigrationIncomingState *mis;
    int ret;

    mis = migration_incoming_state_init(f);

    ret = qemu_loadvm_state(f);

    DPRINTF("%s: ret=%d postcopy_ram_state=%d", __func__, ret,
            mis->postcopy_ram_state);
    if (mis->postcopy_ram_state == POSTCOPY_RAM_INCOMING_ADVISE) {
        /*
         * Where a migration had postcopy enabled (and thus went to advise)
         * but managed to complete within the precopy period
         */
        postcopy_ram_incoming_cleanup(mis);
    } else {
        if ((ret >= 0) &&
            (mis->postcopy_ram_state > POSTCOPY_RAM_INCOMING_ADVISE)) {
            /*
             * Postcopy was started, cleanup should happen at the end of the
             * postcopy thread.
             */
            DPRINTF("process_incoming_migration_co: exiting main branch");
            return;
        }
    }

    qemu_fclose(f);
    free_xbzrle_decoded_buf();
    migration_incoming_state_destroy();

    if (ret < 0) {
        error_report("load of migration failed: %s", strerror(-ret));
        exit(EXIT_FAILURE);
    }
    qemu_announce_self();

    bdrv_clear_incoming_migration_all();
    /* Make sure all file formats flush their mutable metadata */
    bdrv_invalidate_cache_all(&local_err);
    if (local_err) {
        qerror_report_err(local_err);
        error_free(local_err);
        exit(EXIT_FAILURE);
    }

    if (autostart) {
        vm_start();
    } else {
        runstate_set(RUN_STATE_PAUSED);
    }
}

void process_incoming_migration(QEMUFile *f)
{
    Coroutine *co = qemu_coroutine_create(process_incoming_migration_co);
    int fd = qemu_get_fd(f);

    assert(fd != -1);
    qemu_set_nonblock(fd);
    qemu_coroutine_enter(co, f);
}

/* amount of nanoseconds we are willing to wait for migration to be down.
 * the choice of nanoseconds is because it is the maximum resolution that
 * get_clock() can achieve. It is an internal measure. All user-visible
 * units must be in seconds */
static uint64_t max_downtime = 300000000;

uint64_t migrate_max_downtime(void)
{
    return max_downtime;
}

MigrationCapabilityStatusList *qmp_query_migrate_capabilities(Error **errp)
{
    MigrationCapabilityStatusList *head = NULL;
    MigrationCapabilityStatusList *caps;
    MigrationState *s = migrate_get_current();
    int i;

    caps = NULL; /* silence compiler warning */
    for (i = 0; i < MIGRATION_CAPABILITY_MAX; i++) {
        if (head == NULL) {
            head = g_malloc0(sizeof(*caps));
            caps = head;
        } else {
            caps->next = g_malloc0(sizeof(*caps));
            caps = caps->next;
        }
        caps->value =
            g_malloc(sizeof(*caps->value));
        caps->value->capability = i;
        caps->value->state = s->enabled_capabilities[i];
    }

    return head;
}

/*
 * Return true if we're already in the middle of a migration
 * (i.e. any of the active or setup states)
 */
static bool migration_already_active(MigrationState *ms)
{
    switch (ms->state) {
    case MIG_STATE_ACTIVE:
    case MIG_STATE_POSTCOPY_ACTIVE:
    case MIG_STATE_SETUP:
        return true;

    default:
        return false;

    }
}

static void get_xbzrle_cache_stats(MigrationInfo *info)
{
    if (migrate_use_xbzrle()) {
        info->has_xbzrle_cache = true;
        info->xbzrle_cache = g_malloc0(sizeof(*info->xbzrle_cache));
        info->xbzrle_cache->cache_size = migrate_xbzrle_cache_size();
        info->xbzrle_cache->bytes = xbzrle_mig_bytes_transferred();
        info->xbzrle_cache->pages = xbzrle_mig_pages_transferred();
        info->xbzrle_cache->cache_miss = xbzrle_mig_pages_cache_miss();
        info->xbzrle_cache->cache_miss_rate = xbzrle_mig_cache_miss_rate();
        info->xbzrle_cache->overflow = xbzrle_mig_pages_overflow();
    }
}

MigrationInfo *qmp_query_migrate(Error **errp)
{
    MigrationInfo *info = g_malloc0(sizeof(*info));
    MigrationState *s = migrate_get_current();

    switch (s->state) {
    case MIG_STATE_NONE:
        /* no migration has happened ever */
        break;
    case MIG_STATE_SETUP:
        info->has_status = true;
        info->status = g_strdup("setup");
        info->has_total_time = false;
        break;
    case MIG_STATE_ACTIVE:
    case MIG_STATE_CANCELLING:
        info->has_status = true;
        info->status = g_strdup("active");
        info->has_total_time = true;
        info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
            - s->total_time;
        info->has_expected_downtime = true;
        info->expected_downtime = s->expected_downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        info->has_ram = true;
        info->ram = g_malloc0(sizeof(*info->ram));
        info->ram->transferred = ram_bytes_transferred();
        info->ram->remaining = ram_bytes_remaining();
        info->ram->total = ram_bytes_total();
        info->ram->duplicate = dup_mig_pages_transferred();
        info->ram->skipped = skipped_mig_pages_transferred();
        info->ram->normal = norm_mig_pages_transferred();
        info->ram->normal_bytes = norm_mig_bytes_transferred();
        info->ram->dirty_pages_rate = s->dirty_pages_rate;
        info->ram->mbps = s->mbps;
        info->ram->dirty_sync_count = s->dirty_sync_count;

        if (blk_mig_active()) {
            info->has_disk = true;
            info->disk = g_malloc0(sizeof(*info->disk));
            info->disk->transferred = blk_mig_bytes_transferred();
            info->disk->remaining = blk_mig_bytes_remaining();
            info->disk->total = blk_mig_bytes_total();
        }

        get_xbzrle_cache_stats(info);
        break;
    case MIG_STATE_POSTCOPY_ACTIVE:
        /* Mostly the same as active; TODO add some postcopy stats */
        info->has_status = true;
        info->status = g_strdup("postcopy-active");
        info->has_total_time = true;
        info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
            - s->total_time;
        info->has_expected_downtime = true;
        info->expected_downtime = s->expected_downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        info->has_ram = true;
        info->ram = g_malloc0(sizeof(*info->ram));
        info->ram->transferred = ram_bytes_transferred();
        info->ram->remaining = ram_bytes_remaining();
        info->ram->total = ram_bytes_total();
        info->ram->duplicate = dup_mig_pages_transferred();
        info->ram->skipped = skipped_mig_pages_transferred();
        info->ram->normal = norm_mig_pages_transferred();
        info->ram->normal_bytes = norm_mig_bytes_transferred();
        info->ram->dirty_pages_rate = s->dirty_pages_rate;
        info->ram->mbps = s->mbps;

        if (blk_mig_active()) {
            info->has_disk = true;
            info->disk = g_malloc0(sizeof(*info->disk));
            info->disk->transferred = blk_mig_bytes_transferred();
            info->disk->remaining = blk_mig_bytes_remaining();
            info->disk->total = blk_mig_bytes_total();
        }

        get_xbzrle_cache_stats(info);
        break;
    case MIG_STATE_COMPLETED:
        get_xbzrle_cache_stats(info);

        info->has_status = true;
        info->status = g_strdup("completed");
        info->has_total_time = true;
        info->total_time = s->total_time;
        info->has_downtime = true;
        info->downtime = s->downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        info->has_ram = true;
        info->ram = g_malloc0(sizeof(*info->ram));
        info->ram->transferred = ram_bytes_transferred();
        info->ram->remaining = 0;
        info->ram->total = ram_bytes_total();
        info->ram->duplicate = dup_mig_pages_transferred();
        info->ram->skipped = skipped_mig_pages_transferred();
        info->ram->normal = norm_mig_pages_transferred();
        info->ram->normal_bytes = norm_mig_bytes_transferred();
        info->ram->mbps = s->mbps;
        info->ram->dirty_sync_count = s->dirty_sync_count;
        break;
    case MIG_STATE_ERROR:
        info->has_status = true;
        info->status = g_strdup("failed");
        break;
    case MIG_STATE_CANCELLED:
        info->has_status = true;
        info->status = g_strdup("cancelled");
        break;
    }

    return info;
}

void qmp_migrate_set_capabilities(MigrationCapabilityStatusList *params,
                                  Error **errp)
{
    MigrationState *s = migrate_get_current();
    MigrationCapabilityStatusList *cap;

    if (migration_already_active(s)) {
        error_set(errp, QERR_MIGRATION_ACTIVE);
        return;
    }

    for (cap = params; cap; cap = cap->next) {
        s->enabled_capabilities[cap->value->capability] = cap->value->state;
    }
}

void qmp_migrate_start_postcopy(Error **errp)
{
    MigrationState *s = migrate_get_current();

    if (!migrate_postcopy_ram()) {
        error_setg(errp, "Enable postcopy with migration_set_capability before"
                         " the start of migration");
        return;
    }

    if (s->state == MIG_STATE_NONE) {
        error_setg(errp, "Postcopy must be started after migration has been"
                         " started");
        return;
    }
    /*
     * we don't error if migration has finished since that would be racy
     * with issuing this command.
     */
    s->start_postcopy = true;
}

/* shared migration helpers */

static void migrate_set_state(MigrationState *s, int old_state, int new_state)
{
    if (atomic_cmpxchg(&s->state, old_state, new_state) == new_state) {
        trace_migrate_set_state(new_state);
    }
}

static void migrate_fd_cleanup_src_rp(MigrationState *ms)
{
    QEMUFile *rp = ms->return_path;

    /*
     * When stuff goes wrong (e.g. failing destination) on the rp, it can get
     * cleaned up from a few threads; make sure not to do it twice in parallel
     */
    rp = atomic_cmpxchg(&ms->return_path, rp, NULL);
    if (rp) {
        DPRINTF("cleaning up return path\n");
        qemu_fclose(rp);
    }
}

static void migrate_fd_cleanup(void *opaque)
{
    MigrationState *s = opaque;

    qemu_bh_delete(s->cleanup_bh);
    s->cleanup_bh = NULL;

    migrate_fd_cleanup_src_rp(s);

    /* This queue generally should be empty - but in the case of a failed
     * migration might have some droppings in.
     */
    struct MigrationSrcPageRequest *mspr, *next_mspr;
    QSIMPLEQ_FOREACH_SAFE(mspr, &s->src_page_requests, next_req, next_mspr) {
        QSIMPLEQ_REMOVE_HEAD(&s->src_page_requests, next_req);
        g_free(mspr);
    }

    if (s->file) {
        trace_migrate_fd_cleanup();
        qemu_mutex_unlock_iothread();
        if (s->started_migration_thread) {
            qemu_thread_join(&s->thread);
            s->started_migration_thread = false;
        }
        qemu_mutex_lock_iothread();

        qemu_fclose(s->file);
        s->file = NULL;
    }

    assert((s->state != MIG_STATE_ACTIVE) &&
           (s->state != MIG_STATE_POSTCOPY_ACTIVE));

    if (s->state != MIG_STATE_COMPLETED) {
        qemu_savevm_state_cancel();
        if (s->state == MIG_STATE_CANCELLING) {
            migrate_set_state(s, MIG_STATE_CANCELLING, MIG_STATE_CANCELLED);
        }
    }

    notifier_list_notify(&migration_state_notifiers, s);
}

void migrate_fd_error(MigrationState *s)
{
    trace_migrate_fd_error();
    assert(s->file == NULL);
    s->state = MIG_STATE_ERROR;
    trace_migrate_set_state(MIG_STATE_ERROR);
    notifier_list_notify(&migration_state_notifiers, s);
}

static void migrate_fd_cancel(MigrationState *s)
{
    int old_state ;
    trace_migrate_fd_cancel();

    if (s->return_path) {
        /* shutdown the rp socket, so causing the rp thread to shutdown */
        qemu_file_shutdown(s->return_path);
    }

    do {
        old_state = s->state;
        if (old_state != MIG_STATE_SETUP && old_state != MIG_STATE_ACTIVE &&
            old_state != MIG_STATE_POSTCOPY_ACTIVE) {
            break;
        }
        migrate_set_state(s, old_state, MIG_STATE_CANCELLING);
    } while (s->state != MIG_STATE_CANCELLING);
}

void add_migration_state_change_notifier(Notifier *notify)
{
    notifier_list_add(&migration_state_notifiers, notify);
}

void remove_migration_state_change_notifier(Notifier *notify)
{
    notifier_remove(notify);
}

bool migration_in_setup(MigrationState *s)
{
    return s->state == MIG_STATE_SETUP;
}

bool migration_has_finished(MigrationState *s)
{
    return s->state == MIG_STATE_COMPLETED;
}

bool migration_has_failed(MigrationState *s)
{
    return (s->state == MIG_STATE_CANCELLED ||
            s->state == MIG_STATE_ERROR);
}

bool migration_postcopy_phase(MigrationState *s)
{
    return (s->state == MIG_STATE_POSTCOPY_ACTIVE);
}

MigrationState *migrate_init(const MigrationParams *params)
{
    MigrationState *s = migrate_get_current();
    int64_t bandwidth_limit = s->bandwidth_limit;
    bool enabled_capabilities[MIGRATION_CAPABILITY_MAX];
    int64_t xbzrle_cache_size = s->xbzrle_cache_size;

    memcpy(enabled_capabilities, s->enabled_capabilities,
           sizeof(enabled_capabilities));

    memset(s, 0, sizeof(*s));
    s->params = *params;
    memcpy(s->enabled_capabilities, enabled_capabilities,
           sizeof(enabled_capabilities));
    s->xbzrle_cache_size = xbzrle_cache_size;

    s->bandwidth_limit = bandwidth_limit;
    s->state = MIG_STATE_SETUP;
    trace_migrate_set_state(MIG_STATE_SETUP);

    qemu_mutex_init(&s->src_page_req_mutex);
    QSIMPLEQ_INIT(&s->src_page_requests);

    s->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    return s;
}

static GSList *migration_blockers;

void migrate_add_blocker(Error *reason)
{
    migration_blockers = g_slist_prepend(migration_blockers, reason);
}

void migrate_del_blocker(Error *reason)
{
    migration_blockers = g_slist_remove(migration_blockers, reason);
}

void qmp_migrate(const char *uri, bool has_blk, bool blk,
                 bool has_inc, bool inc, bool has_detach, bool detach,
                 Error **errp)
{
    Error *local_err = NULL;
    MigrationState *s = migrate_get_current();
    MigrationParams params;
    const char *p;

    params.blk = has_blk && blk;
    params.shared = has_inc && inc;

    if (migration_already_active(s) ||
        s->state == MIG_STATE_CANCELLING) {
        error_set(errp, QERR_MIGRATION_ACTIVE);
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        error_setg(errp, "Guest is waiting for an incoming migration");
        return;
    }

    if (qemu_savevm_state_blocked(errp)) {
        return;
    }

    if (migration_blockers) {
        *errp = error_copy(migration_blockers->data);
        return;
    }

    s = migrate_init(&params);

    if (strstart(uri, "tcp:", &p)) {
        tcp_start_outgoing_migration(s, p, &local_err);
#ifdef CONFIG_RDMA
    } else if (strstart(uri, "rdma:", &p)) {
        rdma_start_outgoing_migration(s, p, &local_err);
#endif
#if !defined(WIN32)
    } else if (strstart(uri, "exec:", &p)) {
        exec_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "unix:", &p)) {
        unix_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "fd:", &p)) {
        fd_start_outgoing_migration(s, p, &local_err);
#endif
    } else {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "uri", "a valid migration protocol");
        s->state = MIG_STATE_ERROR;
        return;
    }

    if (local_err) {
        migrate_fd_error(s);
        error_propagate(errp, local_err);
        return;
    }
}

void qmp_migrate_cancel(Error **errp)
{
    migrate_fd_cancel(migrate_get_current());
}

void qmp_migrate_set_cache_size(int64_t value, Error **errp)
{
    MigrationState *s = migrate_get_current();
    int64_t new_size;

    /* Check for truncation */
    if (value != (size_t)value) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                  "exceeding address space");
        return;
    }

    /* Cache should not be larger than guest ram size */
    if (value > ram_bytes_total()) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                  "exceeds guest ram size ");
        return;
    }

    new_size = xbzrle_cache_resize(value);
    if (new_size < 0) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                  "is smaller than page size");
        return;
    }

    s->xbzrle_cache_size = new_size;
}

int64_t qmp_query_migrate_cache_size(Error **errp)
{
    return migrate_xbzrle_cache_size();
}

void qmp_migrate_set_speed(int64_t value, Error **errp)
{
    MigrationState *s;

    if (value < 0) {
        value = 0;
    }
    if (value > SIZE_MAX) {
        value = SIZE_MAX;
    }

    s = migrate_get_current();
    s->bandwidth_limit = value;
    if (s->file) {
        qemu_file_set_rate_limit(s->file, s->bandwidth_limit / XFER_LIMIT_RATIO);
    }
}

void qmp_migrate_set_downtime(double value, Error **errp)
{
    value *= 1e9;
    value = MAX(0, MIN(UINT64_MAX, value));
    max_downtime = (uint64_t)value;
}

bool migrate_rdma_pin_all(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_RDMA_PIN_ALL];
}

bool migrate_postcopy_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_X_POSTCOPY_RAM];
}

bool migrate_auto_converge(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_AUTO_CONVERGE];
}

bool migrate_zero_blocks(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_ZERO_BLOCKS];
}

int migrate_use_xbzrle(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_XBZRLE];
}

int64_t migrate_xbzrle_cache_size(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->xbzrle_cache_size;
}

/*
 * Something bad happened to the RP stream, mark an error
 * The caller shall print something to indicate why
 */
static void source_return_path_bad(MigrationState *s)
{
    s->rp_state.error = true;
    migrate_fd_cleanup_src_rp(s);
}

/*
 * Process a request for pages received on the return path,
 * We're allowed to send more than requested (e.g. to round to our page size)
 * and we don't need to send pages that have already been sent.
 */
static void migrate_handle_rp_reqpages(MigrationState *ms, const char* rbname,
                                       ram_addr_t start, ram_addr_t len)
{
    DPRINTF("migrate_handle_rp_reqpages: in %s start %zx len %zx",
            rbname, start, len);

    /* Round everything up to our host page size */
    long our_host_ps = sysconf(_SC_PAGESIZE);
    if (start & (our_host_ps-1)) {
        long roundings = start & (our_host_ps-1);
        start -= roundings;
        len += roundings;
    }
    if (len & (our_host_ps-1)) {
        long roundings = len & (our_host_ps-1);
        len -= roundings;
        len += our_host_ps;
    }

    if (ram_save_queue_pages(ms, rbname, start, len)) {
        source_return_path_bad(ms);
    }
}

/*
 * Handles messages sent on the return path towards the source VM
 *
 */
static void *source_return_path_thread(void *opaque)
{
    MigrationState *ms = opaque;
    QEMUFile *rp = ms->return_path;
    uint16_t expected_len, header_len, header_com;
    const int max_len = 512;
    uint8_t buf[max_len];
    uint32_t tmp32;
    uint64_t tmp64a, tmp64b;
    char *tmpstr;
    int res;

    DPRINTF("RP: %s entry", __func__);
    while (rp && !qemu_file_get_error(rp) &&
        migration_already_active(ms)) {
        DPRINTF("RP: %s top of loop", __func__);
        header_com = qemu_get_be16(rp);
        header_len = qemu_get_be16(rp);

        switch (header_com) {
        case MIG_RPCOMM_SHUT:
        case MIG_RPCOMM_ACK:
            expected_len = 4;
            break;

        case MIG_RPCOMM_REQPAGES:
            /* 16 byte start/len _possibly_ plus an id str */
            expected_len = 16 + 256;
            break;

        default:
            error_report("RP: Received invalid cmd 0x%04x length 0x%04x",
                    header_com, header_len);
            source_return_path_bad(ms);
            goto out;
        }

        if (header_len > expected_len) {
            error_report("RP: Received command 0x%04x with"
                    "incorrect length %d expecting %d",
                    header_com, header_len,
                    expected_len);
            source_return_path_bad(ms);
            goto out;
        }

        /* We know we've got a valid header by this point */
        res = qemu_get_buffer(rp, buf, header_len);
        if (res != header_len) {
            DPRINTF("RP: Failed to read command data");
            source_return_path_bad(ms);
            goto out;
        }

        /* OK, we have the command and the data */
        switch (header_com) {
        case MIG_RPCOMM_SHUT:
            tmp32 = be32_to_cpup((uint32_t *)buf);
            if (tmp32) {
                error_report("RP: Sibling indicated error %d", tmp32);
                source_return_path_bad(ms);
            } else {
                DPRINTF("RP: SHUT received");
            }
            /*
             * We'll let the main thread deal with closing the RP
             * we could do a shutdown(2) on it, but we're the only user
             * anyway, so there's nothing gained.
             */
            goto out;

        case MIG_RPCOMM_ACK:
            tmp32 = be32_to_cpup((uint32_t *)buf);
            DPRINTF("RP: Received ACK 0x%x", tmp32);
            atomic_xchg(&ms->rp_state.latest_ack, tmp32);
            break;

        case MIG_RPCOMM_REQPAGES:
            tmp64a = be64_to_cpup((uint64_t *)buf);  /* Start */
            tmp64b = be64_to_cpup(((uint64_t *)buf)+1); /* Len */
            tmpstr = NULL;
            if (tmp64b & 1) {
                tmp64b -= 1; /* Remove the flag */
                /* Now we expect an idstr */
                tmp32 = buf[16]; /* Length of the following idstr */
                tmpstr = (char *)&buf[17];
                buf[17+tmp32] = '\0';
                expected_len = 16+1+tmp32;
            } else {
                expected_len = 16;
            }
            if (header_len != expected_len) {
                error_report("RP: Received ReqPage with length %d expecting %d",
                        header_len, expected_len);
                source_return_path_bad(ms);
            }
            migrate_handle_rp_reqpages(ms, tmpstr,
                                          (ram_addr_t)tmp64a,
                                          (ram_addr_t)tmp64b);
            break;

        default:
            /* This shouldn't happen because we should catch this above */
            DPRINTF("RP: Bad header_com in dispatch");
        }
        /* Latest command processed, now leave a gap for the next one */
        header_com = MIG_RPCOMM_INVALID;
    }
    if (rp && qemu_file_get_error(rp)) {
        DPRINTF("%s: rp bad at end", __func__);
        source_return_path_bad(ms);
    }

    DPRINTF("%s: Bottom exit", __func__);

out:
    return NULL;
}

static int open_outgoing_return_path(MigrationState *ms)
{

    ms->return_path = qemu_file_get_return_path(ms->file);
    if (!ms->return_path) {
        return -1;
    }

    DPRINTF("%s: starting thread", __func__);
    qemu_thread_create(&ms->rp_state.rp_thread, "return path",
                       source_return_path_thread, ms, QEMU_THREAD_JOINABLE);

    DPRINTF("%s: continuing", __func__);

    return 0;
}

static void await_outgoing_return_path_close(MigrationState *ms)
{
    /*
     * If this is a normal exit then the destination will send a SHUT and the
     * rp_thread will exit, however if there's an error we need to cause
     * it to exit, which we can do by a shutdown.
     * (canceling must also shutdown to stop us getting stuck here if
     * the destination died at just the wrong place)
     */
    if (qemu_file_get_error(ms->file) && ms->return_path) {
        qemu_file_shutdown(ms->return_path);
    }
    DPRINTF("%s: Joining", __func__);
    qemu_thread_join(&ms->rp_state.rp_thread);
    DPRINTF("%s: Exit", __func__);
}

/* Switch from normal iteration to postcopy
 * Returns non-0 on error
 */
static int postcopy_start(MigrationState *ms)
{
    int ret;
    const QEMUSizedBuffer *qsb;
    migrate_set_state(ms, MIG_STATE_ACTIVE, MIG_STATE_POSTCOPY_ACTIVE);

    DPRINTF("postcopy_start\n");
    qemu_mutex_lock_iothread();
    DPRINTF("postcopy_start: setting run state\n");
    ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);

    if (ret < 0) {
        migrate_set_state(ms, MIG_STATE_POSTCOPY_ACTIVE, MIG_STATE_ERROR);
        qemu_mutex_unlock_iothread();
        return -1;
    }

    /*
     * in Finish migrate and with the io-lock held everything should
     * be quiet, but we've potentially still got dirty pages and we
     * need to tell the destination to throw any pages it's already received
     * that are dirty
     */
    if (ram_postcopy_send_discard_bitmap(ms)) {
        DPRINTF("postcopy send discard bitmap failed\n");
        migrate_set_state(ms, MIG_STATE_POSTCOPY_ACTIVE, MIG_STATE_ERROR);
        qemu_mutex_unlock_iothread();
        return -1;
    }

    DPRINTF("postcopy_start: sending req 2\n");
    qemu_savevm_send_reqack(ms->file, 2);
    /*
     * send rest of state - note things that are doing postcopy
     * will notice we're in MIG_STATE_POSTCOPY_ACTIVE and not actually
     * wrap their state up here
     */
    qemu_file_set_rate_limit(ms->file, INT64_MAX);
    DPRINTF("postcopy_start: do state_complete\n");

    /*
     * We need to leave the fd free for page transfers during the
     * loading of the device state, so wrap all the remaining
     * commands and state into a package that gets sent in one go
     */
    QEMUFile *fb = qemu_bufopen("w", NULL);
    if (!fb) {
        error_report("Failed to create buffered file");
        migrate_set_state(ms, MIG_STATE_POSTCOPY_ACTIVE, MIG_STATE_ERROR);
        qemu_mutex_unlock_iothread();
        return -1;
    }

    /*
     * Make sure the receiver can get incoming pages before we send the rest
     * of the state
     */
    qemu_savevm_send_postcopy_ram_listen(fb);

    qemu_savevm_state_complete(fb);
    DPRINTF("postcopy_start: sending req 3\n");
    qemu_savevm_send_reqack(fb, 3);

    qemu_savevm_send_postcopy_ram_run(fb);

    /* <><> end of stuff going into the package */
    qsb = qemu_buf_get(fb);

    /* Now send that blob */
    if (qsb_get_length(qsb) > MAX_VM_CMD_PACKAGED_SIZE) {
        DPRINTF("postcopy_start: Unreasonably large packaged state: %lu\n",
                (unsigned long)(qsb_get_length(qsb)));
        migrate_set_state(ms, MIG_STATE_POSTCOPY_ACTIVE, MIG_STATE_ERROR);
        qemu_mutex_unlock_iothread();
        qemu_fclose(fb);
        return -1;
    }
    qemu_savevm_send_packaged(ms->file, qsb);
    qemu_fclose(fb);

    qemu_mutex_unlock_iothread();

    DPRINTF("postcopy_start not finished sending ack\n");
    qemu_savevm_send_reqack(ms->file, 4);

    ret = qemu_file_get_error(ms->file);
    if (ret) {
        error_report("postcopy_start: Migration stream errored");
        migrate_set_state(ms, MIG_STATE_POSTCOPY_ACTIVE, MIG_STATE_ERROR);
    }

    return ret;
}

/*
 * Master migration thread on the source VM.
 * It drives the migration and pumps the data down the outgoing channel.
 */
static void *migration_thread(void *opaque)
{
    MigrationState *s = opaque;
    /* Used by the bandwidth calcs, updated later */
    int64_t initial_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int64_t setup_start = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    int64_t initial_bytes = 0;
    int64_t max_size = 0;
    int64_t start_time = initial_time;

    bool old_vm_running = false;

    /* The active state we expect to be in; ACTIVE or POSTCOPY_ACTIVE */
    enum MigrationPhase current_active_type = MIG_STATE_ACTIVE;

    qemu_savevm_state_begin(s->file, &s->params);

    if (migrate_postcopy_ram()) {
        /* Now tell the dest that it should open it's end so it can reply */
        qemu_savevm_send_openrp(s->file);

        /* And ask it to send an ack that will make stuff easier to debug */
        qemu_savevm_send_reqack(s->file, 1);

        /* Tell the destination that we *might* want to do postcopy later;
         * if the other end can't do postcopy it should fail now, nice and
         * early.
         */
        qemu_savevm_send_postcopy_ram_advise(s->file);
    }

    s->setup_time = qemu_clock_get_ms(QEMU_CLOCK_HOST) - setup_start;
    current_active_type = MIG_STATE_ACTIVE;
    migrate_set_state(s, MIG_STATE_SETUP, MIG_STATE_ACTIVE);

    DPRINTF("setup complete\n");

    while (s->state == MIG_STATE_ACTIVE ||
           s->state == MIG_STATE_POSTCOPY_ACTIVE) {
        int64_t current_time;
        uint64_t pending_size;

        if (!qemu_file_rate_limit(s->file)) {
            uint64_t pend_post, pend_nonpost;
            DPRINTF("iterate\n");
            qemu_savevm_state_pending(s->file, max_size, &pend_nonpost,
                                      &pend_post);
            pending_size = pend_nonpost + pend_post;
            trace_migrate_pending(pending_size, max_size);
            DPRINTF("pending size %" PRIu64 " max %" PRIu64 " (post=%" PRIu64
                    " nonpost=%" PRIu64 ")\n",
                    pending_size, max_size, pend_post, pend_nonpost);
            if (pending_size && pending_size >= max_size) {
                /* Still a significant amount to transfer */

                current_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
                if (migrate_postcopy_ram() &&
                    s->state != MIG_STATE_POSTCOPY_ACTIVE &&
                    pend_nonpost == 0 && s->start_postcopy) {

                    if (!postcopy_start(s)) {
                        current_active_type = MIG_STATE_POSTCOPY_ACTIVE;
                    }

                    continue;
                }
                /* Just another iteration step */
                qemu_savevm_state_iterate(s->file);
            } else {
                int ret;

                DPRINTF("done iterating pending size %" PRIu64 "\n",
                        pending_size);

                if (s->state == MIG_STATE_ACTIVE) {
                    qemu_mutex_lock_iothread();
                    start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
                    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER);
                    old_vm_running = runstate_is_running();

                    ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);
                    if (ret >= 0) {
                        qemu_file_set_rate_limit(s->file, INT64_MAX);
                        qemu_savevm_state_complete(s->file);
                    }
                    qemu_mutex_unlock_iothread();

                    if (ret < 0) {
                        migrate_set_state(s, current_active_type,
                                          MIG_STATE_ERROR);
                        break;
                    }
                } else if (s->state == MIG_STATE_POSTCOPY_ACTIVE) {
                    DPRINTF("postcopy end\n");

                    qemu_savevm_state_postcopy_complete(s->file);
                    DPRINTF("postcopy end after complete\n");

                }

                /*
                 * If rp was opened we must clean up the thread before
                 * cleaning everything else up.
                 * Postcopy opens rp if enabled (even if it's not avtivated)
                 */
                if (migrate_postcopy_ram()) {
                    DPRINTF("before rp close");
                    await_outgoing_return_path_close(s);
                    DPRINTF("after rp close");
                }
                if (!qemu_file_get_error(s->file)) {
                    migrate_set_state(s, current_active_type,
                                      MIG_STATE_COMPLETED);
                    break;
                }
            }
        }

        if (qemu_file_get_error(s->file)) {
            migrate_set_state(s, current_active_type, MIG_STATE_ERROR);
            DPRINTF("migration_thread: file is in error state\n");
            break;
        }
        current_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        if (current_time >= initial_time + BUFFER_DELAY) {
            uint64_t transferred_bytes = qemu_ftell(s->file) - initial_bytes;
            uint64_t time_spent = current_time - initial_time;
            double bandwidth = transferred_bytes / time_spent;
            max_size = bandwidth * migrate_max_downtime() / 1000000;

            s->mbps = time_spent ? (((double) transferred_bytes * 8.0) /
                    ((double) time_spent / 1000.0)) / 1000.0 / 1000.0 : -1;

            trace_migrate_transferred(transferred_bytes, time_spent,
                                      bandwidth, max_size);
            /* if we haven't sent anything, we don't want to recalculate
               10000 is a small enough number for our purposes */
            if (s->dirty_bytes_rate && transferred_bytes > 10000) {
                s->expected_downtime = s->dirty_bytes_rate / bandwidth;
            }

            qemu_file_reset_rate_limit(s->file);
            initial_time = current_time;
            initial_bytes = qemu_ftell(s->file);
        }
        if (qemu_file_rate_limit(s->file)) {
            /* usleep expects microseconds */
            g_usleep((initial_time + BUFFER_DELAY - current_time)*1000);
        }
    }

    DPRINTF("migration_thread: After loop");
    qemu_mutex_lock_iothread();
    if (s->state == MIG_STATE_COMPLETED) {
        int64_t end_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        uint64_t transferred_bytes = qemu_ftell(s->file);
        s->total_time = end_time - s->total_time;
        s->downtime = end_time - start_time;
        if (s->total_time) {
            s->mbps = (((double) transferred_bytes * 8.0) /
                       ((double) s->total_time)) / 1000;
        }
        runstate_set(RUN_STATE_POSTMIGRATE);
    } else {
        if (old_vm_running) {
            vm_start();
        }
    }
    qemu_bh_schedule(s->cleanup_bh);
    qemu_mutex_unlock_iothread();

    return NULL;
}

void migrate_fd_connect(MigrationState *s)
{
    s->state = MIG_STATE_SETUP;
    trace_migrate_set_state(MIG_STATE_SETUP);

    /* This is a best 1st approximation. ns to ms */
    s->expected_downtime = max_downtime/1000000;
    s->cleanup_bh = qemu_bh_new(migrate_fd_cleanup, s);

    qemu_file_set_rate_limit(s->file,
                             s->bandwidth_limit / XFER_LIMIT_RATIO);

    /* Notify before starting migration thread */
    notifier_list_notify(&migration_state_notifiers, s);

    /* Open the return path; currently for postcopy but other things might
     * also want it.
     */
    if (migrate_postcopy_ram()) {
        if (open_outgoing_return_path(s)) {
            error_report("Unable to open return-path for postcopy");
            migrate_set_state(s, MIG_STATE_SETUP, MIG_STATE_ERROR);
            migrate_fd_cleanup(s);
            return;
        }
    }

    qemu_thread_create(&s->thread, "migration", migration_thread, s,
                       QEMU_THREAD_JOINABLE);
    s->started_migration_thread = true;
}
