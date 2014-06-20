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
 */

#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

#include "qapi/qmp/qdict.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/notify.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "qapi-types.h"
#include "exec/cpu-common.h"

#define QEMU_VM_FILE_MAGIC           0x5145564d
#define QEMU_VM_FILE_VERSION_COMPAT  0x00000002
#define QEMU_VM_FILE_VERSION         0x00000003

#define QEMU_VM_EOF                  0x00
#define QEMU_VM_SECTION_START        0x01
#define QEMU_VM_SECTION_PART         0x02
#define QEMU_VM_SECTION_END          0x03
#define QEMU_VM_SECTION_FULL         0x04
#define QEMU_VM_SUBSECTION           0x05
#define QEMU_VM_COMMAND              0x06

struct MigrationParams {
    bool blk;
    bool shared;
};

/* Commands sent on the return path from destination to source*/
enum mig_rpcomm_cmd {
    MIG_RPCOMM_INVALID = 0,  /* Must be 0 */
    MIG_RPCOMM_SHUT,         /* sibling will not send any more RP messages */
    MIG_RPCOMM_ACK,          /* data (seq: be32 ) */
    MIG_RPCOMM_AFTERLASTVALID
};

/* Source side RP state */
struct MigrationRetPathState {
    uint32_t      latest_ack;
    QemuThread    rp_thread;
    bool          error;
};

typedef struct MigrationState MigrationState;

/* Postcopy page-map-incoming - data about each page on the inbound side */

typedef enum {
   POSTCOPY_PMI_MISSING,   /* page hasn't yet been received */
   POSTCOPY_PMI_REQUESTED, /* Kernel asked for a page, but we've not got it */
   POSTCOPY_PMI_RECEIVED   /* We've got the page */
} PostcopyPMIState;

struct PostcopyPMI {
    QemuMutex      mutex;
    unsigned long *received_map;  /* Pages that we have received */
    unsigned long *requested_map; /* Pages that we're sending a request for */
    unsigned long  host_mask;     /* A mask with enough bits set to cover one
                                     host page in the PMI */
    unsigned long  host_bits;     /* The number of bits in the map representing
                                     one host page */
};

/* State for the incoming migration */
struct MigrationIncomingState {
    QEMUFile *file;

    volatile enum {
        POSTCOPY_RAM_INCOMING_NONE = 0,  /* Initial state - no postcopy */
        POSTCOPY_RAM_INCOMING_ADVISE,
        POSTCOPY_RAM_INCOMING_LISTENING,
        POSTCOPY_RAM_INCOMING_RUNNING,
        POSTCOPY_RAM_INCOMING_END
    } postcopy_ram_state;

    QEMUFile *return_path;
    QemuMutex      rp_mutex;    /* We send replies from multiple threads */
    PostcopyPMI    postcopy_pmi;
};

MigrationIncomingState *migration_incoming_get_current(void);
MigrationIncomingState *migration_incoming_state_init(QEMUFile *f);
void migration_incoming_state_destroy(void);

struct MigrationState
{
    int64_t bandwidth_limit;
    size_t bytes_xfer;
    size_t xfer_limit;
    QemuThread thread;
    QEMUBH *cleanup_bh;
    QEMUFile *file;
    QEMUFile *return_path;

    int state;
    MigrationParams params;
    struct MigrationRetPathState rp_state;
    double mbps;
    int64_t total_time;
    int64_t downtime;
    int64_t expected_downtime;
    int64_t dirty_pages_rate;
    int64_t dirty_bytes_rate;
    bool enabled_capabilities[MIGRATION_CAPABILITY_MAX];
    int64_t xbzrle_cache_size;
    int64_t setup_time;
    int64_t dirty_sync_count;

    /* Flag set once the migration has been asked to enter postcopy */
    volatile bool start_postcopy;

    /* bitmap of pages that have been sent at least once
     * only maintained and used in postcopy at the moment
     * where it's used to send the dirtymap at the start
     * of the postcopy phase
     */
    unsigned long *sentmap;
};

void process_incoming_migration(QEMUFile *f);

void qemu_start_incoming_migration(const char *uri, Error **errp);

uint64_t migrate_max_downtime(void);

void do_info_migrate_print(Monitor *mon, const QObject *data);

void do_info_migrate(Monitor *mon, QObject **ret_data);

void exec_start_incoming_migration(const char *host_port, Error **errp);

void exec_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void tcp_start_incoming_migration(const char *host_port, Error **errp);

void tcp_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void unix_start_incoming_migration(const char *path, Error **errp);

void unix_start_outgoing_migration(MigrationState *s, const char *path, Error **errp);

void fd_start_incoming_migration(const char *path, Error **errp);

void fd_start_outgoing_migration(MigrationState *s, const char *fdname, Error **errp);

void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp);

void rdma_start_incoming_migration(const char *host_port, Error **errp);

void migrate_fd_error(MigrationState *s);

void migrate_fd_connect(MigrationState *s);

int migrate_fd_close(MigrationState *s);

void add_migration_state_change_notifier(Notifier *notify);
void remove_migration_state_change_notifier(Notifier *notify);
MigrationState *migrate_init(const MigrationParams *params);
bool migration_in_setup(MigrationState *);
bool migration_has_finished(MigrationState *);
bool migration_has_failed(MigrationState *);
/* True if outgoing migration has entered postcopy phase */
bool migration_postcopy_phase(MigrationState *);
MigrationState *migrate_get_current(void);

uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_transferred(void);
uint64_t ram_bytes_total(void);
void free_xbzrle_decoded_buf(void);

void acct_update_position(QEMUFile *f, size_t size, bool zero);

uint64_t dup_mig_bytes_transferred(void);
uint64_t dup_mig_pages_transferred(void);
uint64_t skipped_mig_bytes_transferred(void);
uint64_t skipped_mig_pages_transferred(void);
uint64_t norm_mig_bytes_transferred(void);
uint64_t norm_mig_pages_transferred(void);
uint64_t xbzrle_mig_bytes_transferred(void);
uint64_t xbzrle_mig_pages_transferred(void);
uint64_t xbzrle_mig_pages_overflow(void);
uint64_t xbzrle_mig_pages_cache_miss(void);
double xbzrle_mig_cache_miss_rate(void);

void ram_handle_compressed(void *host, uint8_t ch, uint64_t size);
void ram_debug_dump_bitmap(unsigned long *todump, bool expected);
/* For outgoing discard bitmap */
int ram_postcopy_send_discard_bitmap(MigrationState *ms);
/* For incoming postcopy discard */
int ram_discard_range(MigrationIncomingState *mis, const char *block_name,
                      uint64_t start, uint64_t end);
int ram_postcopy_incoming_init(MigrationIncomingState *mis);

/**
 * @migrate_add_blocker - prevent migration from proceeding
 *
 * @reason - an error to be returned whenever migration is attempted
 */
void migrate_add_blocker(Error *reason);

/**
 * @migrate_del_blocker - remove a blocking error from migration
 *
 * @reason - the error blocking migration
 */
void migrate_del_blocker(Error *reason);

bool migrate_postcopy_ram(void);
bool migrate_rdma_pin_all(void);
bool migrate_zero_blocks(void);

bool migrate_auto_converge(void);

int xbzrle_encode_buffer(uint8_t *old_buf, uint8_t *new_buf, int slen,
                         uint8_t *dst, int dlen);
int xbzrle_decode_buffer(uint8_t *src, int slen, uint8_t *dst, int dlen);

int migrate_use_xbzrle(void);
int64_t migrate_xbzrle_cache_size(void);

int64_t xbzrle_cache_resize(int64_t new_size);

/* Sending on the return path - generic and then for each message type */
void migrate_send_rp_message(MigrationIncomingState *mis,
                             enum mig_rpcomm_cmd cmd,
                             uint16_t len, uint8_t *data);
void migrate_send_rp_shut(MigrationIncomingState *mis,
                          uint32_t value);
void migrate_send_rp_ack(MigrationIncomingState *mis,
                         uint32_t value);


void ram_control_before_iterate(QEMUFile *f, uint64_t flags);
void ram_control_after_iterate(QEMUFile *f, uint64_t flags);
void ram_control_load_hook(QEMUFile *f, uint64_t flags);

/* Whenever this is found in the data stream, the flags
 * will be passed to ram_control_load_hook in the incoming-migration
 * side. This lets before_ram_iterate/after_ram_iterate add
 * transport-specific sections to the RAM migration data.
 */
#define RAM_SAVE_FLAG_HOOK     0x80

#define RAM_SAVE_CONTROL_NOT_SUPP -1000
#define RAM_SAVE_CONTROL_DELAYED  -2000

size_t ram_control_save_page(QEMUFile *f, ram_addr_t block_offset,
                             ram_addr_t offset, size_t size,
                             int *bytes_sent);

#endif
