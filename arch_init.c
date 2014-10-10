/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/mman.h>
#endif
#include "config.h"
#include "monitor/monitor.h"
#include "sysemu/sysemu.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "sysemu/arch_init.h"
#include "audio/audio.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/audio/audio.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "migration/postcopy-ram.h"
#include "hw/i386/smbios.h"
#include "exec/address-spaces.h"
#include "hw/audio/pcspk.h"
#include "migration/page_cache.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qmp-commands.h"
#include "trace.h"
#include "exec/cpu-all.h"
#include "exec/ram_addr.h"
#include "hw/acpi/acpi.h"
#include "qemu/host-utils.h"

// #define DEBUG_ARCH_INIT
#ifdef DEBUG_ARCH_INIT
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr,  "arch_init@%" PRId64 " " fmt "\n", \
                          qemu_clock_get_ms(QEMU_CLOCK_REALTIME), \
                          ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef TARGET_SPARC
int graphic_width = 1024;
int graphic_height = 768;
int graphic_depth = 8;
#else
int graphic_width = 800;
int graphic_height = 600;
int graphic_depth = 32;
#endif


#if defined(TARGET_ALPHA)
#define QEMU_ARCH QEMU_ARCH_ALPHA
#elif defined(TARGET_ARM)
#define QEMU_ARCH QEMU_ARCH_ARM
#elif defined(TARGET_CRIS)
#define QEMU_ARCH QEMU_ARCH_CRIS
#elif defined(TARGET_I386)
#define QEMU_ARCH QEMU_ARCH_I386
#elif defined(TARGET_M68K)
#define QEMU_ARCH QEMU_ARCH_M68K
#elif defined(TARGET_LM32)
#define QEMU_ARCH QEMU_ARCH_LM32
#elif defined(TARGET_MICROBLAZE)
#define QEMU_ARCH QEMU_ARCH_MICROBLAZE
#elif defined(TARGET_MIPS)
#define QEMU_ARCH QEMU_ARCH_MIPS
#elif defined(TARGET_MOXIE)
#define QEMU_ARCH QEMU_ARCH_MOXIE
#elif defined(TARGET_OPENRISC)
#define QEMU_ARCH QEMU_ARCH_OPENRISC
#elif defined(TARGET_PPC)
#define QEMU_ARCH QEMU_ARCH_PPC
#elif defined(TARGET_S390X)
#define QEMU_ARCH QEMU_ARCH_S390X
#elif defined(TARGET_SH4)
#define QEMU_ARCH QEMU_ARCH_SH4
#elif defined(TARGET_SPARC)
#define QEMU_ARCH QEMU_ARCH_SPARC
#elif defined(TARGET_XTENSA)
#define QEMU_ARCH QEMU_ARCH_XTENSA
#elif defined(TARGET_UNICORE32)
#define QEMU_ARCH QEMU_ARCH_UNICORE32
#elif defined(TARGET_TRICORE)
#define QEMU_ARCH QEMU_ARCH_TRICORE
#endif

const uint32_t arch_type = QEMU_ARCH;
static bool mig_throttle_on;
static int dirty_rate_high_cnt;
static void check_guest_throttling(void);

static uint64_t bitmap_sync_count;

/***********************************************************/
/* ram save/restore */

#define RAM_SAVE_FLAG_FULL     0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_COMPRESS 0x02
#define RAM_SAVE_FLAG_MEM_SIZE 0x04
#define RAM_SAVE_FLAG_PAGE     0x08
#define RAM_SAVE_FLAG_EOS      0x10
#define RAM_SAVE_FLAG_CONTINUE 0x20
#define RAM_SAVE_FLAG_XBZRLE   0x40
/* 0x80 is reserved in migration.h start with 0x100 next */

static struct defconfig_file {
    const char *filename;
    /* Indicates it is an user config file (disabled by -no-user-config) */
    bool userconfig;
} default_config_files[] = {
    { CONFIG_QEMU_CONFDIR "/qemu.conf",                   true },
    { CONFIG_QEMU_CONFDIR "/target-" TARGET_NAME ".conf", true },
    { NULL }, /* end of list */
};

static const uint8_t ZERO_TARGET_PAGE[TARGET_PAGE_SIZE];

int qemu_read_default_config_files(bool userconfig)
{
    int ret;
    struct defconfig_file *f;

    for (f = default_config_files; f->filename; f++) {
        if (!userconfig && f->userconfig) {
            continue;
        }
        ret = qemu_read_config_file(f->filename);
        if (ret < 0 && ret != -ENOENT) {
            return ret;
        }
    }

    return 0;
}

static inline bool is_zero_range(uint8_t *p, uint64_t size)
{
    return buffer_find_nonzero_offset(p, size) == size;
}

/* struct contains XBZRLE cache and a static page
   used by the compression */
static struct {
    /* buffer used for XBZRLE encoding */
    uint8_t *encoded_buf;
    /* buffer for storing page content */
    uint8_t *current_buf;
    /* Cache for XBZRLE, Protected by lock. */
    PageCache *cache;
    QemuMutex lock;
} XBZRLE;

/* buffer used for XBZRLE decoding */
static uint8_t *xbzrle_decoded_buf;

static void XBZRLE_cache_lock(void)
{
    if (migrate_use_xbzrle())
        qemu_mutex_lock(&XBZRLE.lock);
}

static void XBZRLE_cache_unlock(void)
{
    if (migrate_use_xbzrle())
        qemu_mutex_unlock(&XBZRLE.lock);
}

/*
 * called from qmp_migrate_set_cache_size in main thread, possibly while
 * a migration is in progress.
 * A running migration maybe using the cache and might finish during this
 * call, hence changes to the cache are protected by XBZRLE.lock().
 */
int64_t xbzrle_cache_resize(int64_t new_size)
{
    PageCache *new_cache;
    int64_t ret;

    if (new_size < TARGET_PAGE_SIZE) {
        return -1;
    }

    XBZRLE_cache_lock();

    if (XBZRLE.cache != NULL) {
        if (pow2floor(new_size) == migrate_xbzrle_cache_size()) {
            goto out_new_size;
        }
        new_cache = cache_init(new_size / TARGET_PAGE_SIZE,
                                        TARGET_PAGE_SIZE);
        if (!new_cache) {
            error_report("Error creating cache");
            ret = -1;
            goto out;
        }

        cache_fini(XBZRLE.cache);
        XBZRLE.cache = new_cache;
    }

out_new_size:
    ret = pow2floor(new_size);
out:
    XBZRLE_cache_unlock();
    return ret;
}

/* accounting for migration statistics */
typedef struct AccountingInfo {
    uint64_t dup_pages;
    uint64_t skipped_pages;
    uint64_t norm_pages;
    uint64_t iterations;
    uint64_t xbzrle_bytes;
    uint64_t xbzrle_pages;
    uint64_t xbzrle_cache_miss;
    double xbzrle_cache_miss_rate;
    uint64_t xbzrle_overflows;
} AccountingInfo;

static AccountingInfo acct_info;

static void acct_clear(void)
{
    memset(&acct_info, 0, sizeof(acct_info));
}

uint64_t dup_mig_bytes_transferred(void)
{
    return acct_info.dup_pages * TARGET_PAGE_SIZE;
}

uint64_t dup_mig_pages_transferred(void)
{
    return acct_info.dup_pages;
}

uint64_t skipped_mig_bytes_transferred(void)
{
    return acct_info.skipped_pages * TARGET_PAGE_SIZE;
}

uint64_t skipped_mig_pages_transferred(void)
{
    return acct_info.skipped_pages;
}

uint64_t norm_mig_bytes_transferred(void)
{
    return acct_info.norm_pages * TARGET_PAGE_SIZE;
}

uint64_t norm_mig_pages_transferred(void)
{
    return acct_info.norm_pages;
}

uint64_t xbzrle_mig_bytes_transferred(void)
{
    return acct_info.xbzrle_bytes;
}

uint64_t xbzrle_mig_pages_transferred(void)
{
    return acct_info.xbzrle_pages;
}

uint64_t xbzrle_mig_pages_cache_miss(void)
{
    return acct_info.xbzrle_cache_miss;
}

double xbzrle_mig_cache_miss_rate(void)
{
    return acct_info.xbzrle_cache_miss_rate;
}

uint64_t xbzrle_mig_pages_overflow(void)
{
    return acct_info.xbzrle_overflows;
}

static size_t save_block_hdr(QEMUFile *f, RAMBlock *block, ram_addr_t offset,
                             int cont, int flag)
{
    size_t size;

    qemu_put_be64(f, offset | cont | flag);
    size = 8;

    if (!cont) {
        qemu_put_byte(f, strlen(block->idstr));
        qemu_put_buffer(f, (uint8_t *)block->idstr,
                        strlen(block->idstr));
        size += 1 + strlen(block->idstr);
    }
    return size;
}

/* This is the last block that we have visited serching for dirty pages
 */
static RAMBlock *last_seen_block;
/* This is the last block from where we have sent data */
static RAMBlock *last_sent_block;
static ram_addr_t last_offset;
static bool last_was_from_queue;
static unsigned long *migration_bitmap;
static uint64_t migration_dirty_pages;
static uint32_t last_version;
static bool ram_bulk_stage;

/* Update the xbzrle cache to reflect a page that's been sent as all 0.
 * The important thing is that a stale (not-yet-0'd) page be replaced
 * by the new data.
 * As a bonus, if the page wasn't in the cache it gets added so that
 * when a small write is made into the 0'd page it gets XBZRLE sent
 */
static void xbzrle_cache_zero_page(ram_addr_t current_addr)
{
    if (ram_bulk_stage || !migrate_use_xbzrle()) {
        return;
    }

    /* We don't care if this fails to allocate a new cache page
     * as long as it updated an old one */
    cache_insert(XBZRLE.cache, current_addr, ZERO_TARGET_PAGE);
}

#define ENCODING_FLAG_XBZRLE 0x1

static int save_xbzrle_page(QEMUFile *f, uint8_t **current_data,
                            ram_addr_t current_addr, RAMBlock *block,
                            ram_addr_t offset, int cont, bool last_stage)
{
    int encoded_len = 0, bytes_sent = -1;
    uint8_t *prev_cached_page;

    if (!cache_is_cached(XBZRLE.cache, current_addr)) {
        acct_info.xbzrle_cache_miss++;
        if (!last_stage) {
            if (cache_insert(XBZRLE.cache, current_addr, *current_data) == -1) {
                return -1;
            } else {
                /* update *current_data when the page has been
                   inserted into cache */
                *current_data = get_cached_data(XBZRLE.cache, current_addr);
            }
        }
        return -1;
    }

    prev_cached_page = get_cached_data(XBZRLE.cache, current_addr);

    /* save current buffer into memory */
    memcpy(XBZRLE.current_buf, *current_data, TARGET_PAGE_SIZE);

    /* XBZRLE encoding (if there is no overflow) */
    encoded_len = xbzrle_encode_buffer(prev_cached_page, XBZRLE.current_buf,
                                       TARGET_PAGE_SIZE, XBZRLE.encoded_buf,
                                       TARGET_PAGE_SIZE);
    if (encoded_len == 0) {
        DPRINTF("Skipping unmodified page\n");
        return 0;
    } else if (encoded_len == -1) {
        DPRINTF("Overflow\n");
        acct_info.xbzrle_overflows++;
        /* update data in the cache */
        if (!last_stage) {
            memcpy(prev_cached_page, *current_data, TARGET_PAGE_SIZE);
            *current_data = prev_cached_page;
        }
        return -1;
    }

    /* we need to update the data in the cache, in order to get the same data */
    if (!last_stage) {
        memcpy(prev_cached_page, XBZRLE.current_buf, TARGET_PAGE_SIZE);
    }

    /* Send XBZRLE based compressed page */
    bytes_sent = save_block_hdr(f, block, offset, cont, RAM_SAVE_FLAG_XBZRLE);
    qemu_put_byte(f, ENCODING_FLAG_XBZRLE);
    qemu_put_be16(f, encoded_len);
    qemu_put_buffer(f, XBZRLE.encoded_buf, encoded_len);
    bytes_sent += encoded_len + 1 + 2;
    acct_info.xbzrle_pages++;
    acct_info.xbzrle_bytes += bytes_sent;

    return bytes_sent;
}

/* mr: The region to search for dirty pages in
 * start: Start address (typically so we can continue from previous page)
 * bitoffset: Pointer into which to store the offset into the dirty map
 *            at which the bit was found.
 */
static inline
ram_addr_t migration_bitmap_find_and_reset_dirty(MemoryRegion *mr,
                                                 ram_addr_t start,
                                                 unsigned long *bitoffset)
{
    unsigned long base = mr->ram_addr >> TARGET_PAGE_BITS;
    unsigned long nr = base + (start >> TARGET_PAGE_BITS);
    uint64_t mr_size = TARGET_PAGE_ALIGN(memory_region_size(mr));
    unsigned long size = base + (mr_size >> TARGET_PAGE_BITS);

    unsigned long next;

    if (ram_bulk_stage && nr > base) {
        next = nr + 1;
    } else {
        next = find_next_bit(migration_bitmap, size, nr);
    }

    if (next < size) {
        clear_bit(next, migration_bitmap);
        assert(migration_dirty_pages > 0);
        migration_dirty_pages--;
    }
    *bitoffset = next;
    return (next - base) << TARGET_PAGE_BITS;
}

static inline bool migration_bitmap_set_dirty(ram_addr_t addr)
{
    bool ret;
    int nr = addr >> TARGET_PAGE_BITS;

    ret = test_and_set_bit(nr, migration_bitmap);

    if (!ret) {
        migration_dirty_pages++;
    }
    return ret;
}

static inline bool migration_bitmap_clear_dirty(ram_addr_t addr)
{
    bool ret;
    int nr = addr >> TARGET_PAGE_BITS;

    ret = test_and_clear_bit(nr, migration_bitmap);

    if (ret) {
        migration_dirty_pages--;
    }
    return ret;
}

static void migration_bitmap_sync_range(ram_addr_t start, ram_addr_t length)
{
    ram_addr_t addr;
    unsigned long page = BIT_WORD(start >> TARGET_PAGE_BITS);

    /* start address is aligned at the start of a word? */
    if (((page * BITS_PER_LONG) << TARGET_PAGE_BITS) == start) {
        int k;
        int nr = BITS_TO_LONGS(length >> TARGET_PAGE_BITS);
        unsigned long *src = ram_list.dirty_memory[DIRTY_MEMORY_MIGRATION];

        for (k = page; k < page + nr; k++) {
            if (src[k]) {
                unsigned long new_dirty;
                new_dirty = ~migration_bitmap[k];
                migration_bitmap[k] |= src[k];
                new_dirty &= src[k];
                migration_dirty_pages += ctpopl(new_dirty);
                src[k] = 0;
            }
        }
    } else {
        for (addr = 0; addr < length; addr += TARGET_PAGE_SIZE) {
            if (cpu_physical_memory_get_dirty(start + addr,
                                              TARGET_PAGE_SIZE,
                                              DIRTY_MEMORY_MIGRATION)) {
                cpu_physical_memory_reset_dirty(start + addr,
                                                TARGET_PAGE_SIZE,
                                                DIRTY_MEMORY_MIGRATION);
                migration_bitmap_set_dirty(start + addr);
            }
        }
    }
}


/* Needs iothread lock! */

static void migration_bitmap_sync(void)
{
    RAMBlock *block;
    uint64_t num_dirty_pages_init = migration_dirty_pages;
    MigrationState *s = migrate_get_current();
    static int64_t start_time;
    static int64_t bytes_xfer_prev;
    static int64_t num_dirty_pages_period;
    int64_t end_time;
    int64_t bytes_xfer_now;
    static uint64_t xbzrle_cache_miss_prev;
    static uint64_t iterations_prev;

    bitmap_sync_count++;

    if (!bytes_xfer_prev) {
        bytes_xfer_prev = ram_bytes_transferred();
    }

    if (!start_time) {
        start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    }

    trace_migration_bitmap_sync_start();
    address_space_sync_dirty_bitmap(&address_space_memory);

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        migration_bitmap_sync_range(block->mr->ram_addr, block->length);
    }
    trace_migration_bitmap_sync_end(migration_dirty_pages
                                    - num_dirty_pages_init);
    num_dirty_pages_period += migration_dirty_pages - num_dirty_pages_init;
    end_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    /* more than 1 second = 1000 millisecons */
    if (end_time > start_time + 1000) {
        if (migrate_auto_converge()) {
            /* The following detection logic can be refined later. For now:
               Check to see if the dirtied bytes is 50% more than the approx.
               amount of bytes that just got transferred since the last time we
               were in this routine. If that happens >N times (for now N==4)
               we turn on the throttle down logic */
            bytes_xfer_now = ram_bytes_transferred();
            if (s->dirty_pages_rate &&
               (num_dirty_pages_period * TARGET_PAGE_SIZE >
                   (bytes_xfer_now - bytes_xfer_prev)/2) &&
               (dirty_rate_high_cnt++ > 4)) {
                    trace_migration_throttle();
                    mig_throttle_on = true;
                    dirty_rate_high_cnt = 0;
             }
             bytes_xfer_prev = bytes_xfer_now;
        } else {
             mig_throttle_on = false;
        }
        if (migrate_use_xbzrle()) {
            if (iterations_prev != 0) {
                acct_info.xbzrle_cache_miss_rate =
                   (double)(acct_info.xbzrle_cache_miss -
                            xbzrle_cache_miss_prev) /
                   (acct_info.iterations - iterations_prev);
            }
            iterations_prev = acct_info.iterations;
            xbzrle_cache_miss_prev = acct_info.xbzrle_cache_miss;
        }
        s->dirty_pages_rate = num_dirty_pages_period * 1000
            / (end_time - start_time);
        s->dirty_bytes_rate = s->dirty_pages_rate * TARGET_PAGE_SIZE;
        start_time = end_time;
        num_dirty_pages_period = 0;
        s->dirty_sync_count = bitmap_sync_count;
    }
}

static RAMBlock *ram_find_block(const char *id)
{
    RAMBlock *block;

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        if (!strcmp(id, block->idstr)) {
            return block;
        }
    }

    return NULL;
}

/*
 * ram_save_page: Send the given page to the stream
 *
 * Returns: Number of bytes written.
 */
static int ram_save_page(QEMUFile *f, RAMBlock* block, ram_addr_t offset,
                         bool last_stage)
{
    int bytes_sent;
    int cont;
    ram_addr_t current_addr;
    MemoryRegion *mr = block->mr;
    uint8_t *p;
    int ret;
    bool send_async = true;

    cont = (block == last_sent_block) ? RAM_SAVE_FLAG_CONTINUE : 0;

    p = memory_region_get_ram_ptr(mr) + offset;

    /* In doubt sent page as normal */
    bytes_sent = -1;
    ret = ram_control_save_page(f, block->offset,
                           offset, TARGET_PAGE_SIZE, &bytes_sent);

    XBZRLE_cache_lock();

    current_addr = block->offset + offset;
    if (ret != RAM_SAVE_CONTROL_NOT_SUPP) {
        if (ret != RAM_SAVE_CONTROL_DELAYED) {
            if (bytes_sent > 0) {
                acct_info.norm_pages++;
            } else if (bytes_sent == 0) {
                acct_info.dup_pages++;
            }
        }
    } else if (is_zero_range(p, TARGET_PAGE_SIZE)) {
        acct_info.dup_pages++;
        bytes_sent = save_block_hdr(f, block, offset, cont,
                                    RAM_SAVE_FLAG_COMPRESS);
        qemu_put_byte(f, 0);
        bytes_sent++;
        /* Must let xbzrle know, otherwise a previous (now 0'd) cached
         * page would be stale
         */
        xbzrle_cache_zero_page(current_addr);
    } else if (!ram_bulk_stage && migrate_use_xbzrle()) {
        bytes_sent = save_xbzrle_page(f, &p, current_addr, block,
                                      offset, cont, last_stage);
        if (!last_stage) {
            /* Can't send this cached data async, since the cache page
             * might get updated before it gets to the wire
             */
            send_async = false;
        }
    }

    /* XBZRLE overflow or normal page */
    if (bytes_sent == -1) {
        bytes_sent = save_block_hdr(f, block, offset, cont, RAM_SAVE_FLAG_PAGE);
        if (send_async) {
            qemu_put_buffer_async(f, p, TARGET_PAGE_SIZE);
        } else {
            qemu_put_buffer(f, p, TARGET_PAGE_SIZE);
        }
        bytes_sent += TARGET_PAGE_SIZE;
        acct_info.norm_pages++;
    }

    XBZRLE_cache_unlock();

    return bytes_sent;
}

/*
 * Unqueue a page from the queue fed by postcopy page requests
 *
 * Returns:   The RAMBlock* to transmit from (or NULL if the queue is empty)
 *      ms:   MigrationState in
 *  offset:   the byte offset within the RAMBlock for the start of the page
 * bitoffset: global offset in the dirty/sent bitmaps
 */
static RAMBlock *ram_save_unqueue_page(MigrationState *ms, ram_addr_t *offset,
                                       unsigned long *bitoffset)
{
    RAMBlock *result = NULL;
    qemu_mutex_lock(&ms->src_page_req_mutex);
    if (!QSIMPLEQ_EMPTY(&ms->src_page_requests)) {
        struct MigrationSrcPageRequest *entry =
                                    QSIMPLEQ_FIRST(&ms->src_page_requests);
        result = entry->rb;
        *offset = entry->offset;
        *bitoffset = (entry->offset + entry->rb->offset) >> TARGET_PAGE_BITS;

        if (entry->len > TARGET_PAGE_SIZE) {
            entry->len -= TARGET_PAGE_SIZE;
            entry->offset += TARGET_PAGE_SIZE;
        } else {
            QSIMPLEQ_REMOVE_HEAD(&ms->src_page_requests, next_req);
            g_free(entry);
        }
    }
    qemu_mutex_unlock(&ms->src_page_req_mutex);

    return result;
}

/*
 * Queue the pages for transmission, e.g. a request from postcopy destination
 *   ms: MigrationStatus in which the queue is held
 *   rbname: The RAMBlock the request is for - may be NULL (to mean reuse last)
 *   start: Offset from the start of the RAMBlock
 *   len: Length (in bytes) to send
 *   Return: 0 on success
 */
int ram_save_queue_pages(MigrationState *ms, const char *rbname,
                         ram_addr_t start, ram_addr_t len)
{
    RAMBlock *ramblock;

    if (!rbname) {
        /* Reuse last RAMBlock */
        ramblock = ms->last_req_rb;

        if (!ramblock) {
            error_report("ram_save_queue_pages no previous block");
            return -1;
        }
    } else {
        ramblock = ram_find_block(rbname);

        if (!ramblock) {
            error_report("ram_save_queue_pages no block '%s'", rbname);
            return -1;
        }
    }
    DPRINTF("ram_save_queue_pages: Block %s start %zx len %zx",
                    ramblock->idstr, start, len);

    if (start+len > ramblock->length) {
        error_report("%s request overrun start=%zx len=%zx blocklen=%zx",
                     __func__, start, len, ramblock->length);
        return -1;
    }

    struct MigrationSrcPageRequest *new_entry =
        g_malloc0(sizeof(struct MigrationSrcPageRequest));
    new_entry->rb = ramblock;
    new_entry->offset = start;
    new_entry->len = len;
    ms->last_req_rb = ramblock;

    qemu_mutex_lock(&ms->src_page_req_mutex);
    QSIMPLEQ_INSERT_TAIL(&ms->src_page_requests, new_entry, next_req);
    qemu_mutex_unlock(&ms->src_page_req_mutex);

    return 0;
}

/*
 * ram_find_and_save_block: Finds a page to send and sends it to f
 *
 * Returns:  The number of bytes written.
 *           0 means no dirty pages
 */

static int ram_find_and_save_block(QEMUFile *f, bool last_stage)
{
    MigrationState *ms = migrate_get_current();
    RAMBlock *block = last_seen_block;
    RAMBlock *tmpblock;
    ram_addr_t offset = last_offset;
    ram_addr_t tmpoffset;
    bool complete_round = false;
    int bytes_sent = 0;
    unsigned long bitoffset;
    unsigned long hps = sysconf(_SC_PAGESIZE);

    if (!block) {
        block = QTAILQ_FIRST(&ram_list.blocks);
        last_was_from_queue = false;
    }

    while (true) { /* Until we send a block or run out of stuff to send */
        tmpblock = NULL;

        /*
         * Don't break host-page chunks up with queue items
         * so only unqueue if,
         *   a) The last item came from the queue anyway
         *   b) The last sent item was the last target-page in a host page
         */
        if (last_was_from_queue || (!last_sent_block) ||
            ((last_offset & (hps - 1)) == (hps - TARGET_PAGE_SIZE))) {
            tmpblock = ram_save_unqueue_page(ms, &tmpoffset, &bitoffset);
        }

        if (tmpblock) {
            /* We've got a block from the postcopy queue */
            DPRINTF("%s: Got postcopy item '%s' offset=%zx bitoffset=%zx",
                    __func__, tmpblock->idstr, tmpoffset, bitoffset);
            /* We're sending this page, and since it's postcopy nothing else
             * will dirty it, and we must make sure it doesn't get sent again.
             */
            if (!migration_bitmap_clear_dirty(bitoffset << TARGET_PAGE_BITS)) {
                DPRINTF("%s: Not dirty for postcopy %s/%zx bito=%zx (sent=%d)",
                        __func__, tmpblock->idstr, tmpoffset, bitoffset,
                        test_bit(bitoffset, ms->sentmap));
                continue;
            }
            /*
             * As soon as we start servicing pages out of order, then we have
             * to kill the bulk stage, since the bulk stage assumes
             * in (migration_bitmap_find_and_reset_dirty) that every page is
             * dirty, that's no longer true.
             */
            ram_bulk_stage = false;
            /*
             * We mustn't change block/offset unless it's to a valid one
             * otherwise we can go down some of the exit cases in the normal
             * path.
             */
            block = tmpblock;
            offset = tmpoffset;
            last_was_from_queue = true;
        } else {
            MemoryRegion *mr;
            /* priority queue empty, so just search for something dirty */
            mr = block->mr;
            offset = migration_bitmap_find_and_reset_dirty(mr, offset,
                                                           &bitoffset);
            if (complete_round && block == last_seen_block &&
                offset >= last_offset) {
                break;
            }
            if (offset >= block->length) {
                offset = 0;
                block = QTAILQ_NEXT(block, next);
                if (!block) {
                    block = QTAILQ_FIRST(&ram_list.blocks);
                    complete_round = true;
                    ram_bulk_stage = false;
                }
                continue; /* pick an offset in the new block */
            }
            last_was_from_queue = false;
        }

        /* We have a page to send, so send it */
        bytes_sent = ram_save_page(f, block, offset, last_stage);

        /* if page is unmodified, continue to the next */
        if (bytes_sent > 0) {
            if (ms->sentmap) {
                set_bit(bitoffset, ms->sentmap);
            }

            last_sent_block = block;
            break;
        }
    }
    last_seen_block = block;
    last_offset = offset;

    return bytes_sent;
}

static uint64_t bytes_transferred;

void acct_update_position(QEMUFile *f, size_t size, bool zero)
{
    uint64_t pages = size / TARGET_PAGE_SIZE;
    if (zero) {
        acct_info.dup_pages += pages;
    } else {
        acct_info.norm_pages += pages;
        bytes_transferred += size;
        qemu_update_position(f, size);
    }
}

static ram_addr_t ram_save_remaining(void)
{
    return migration_dirty_pages;
}

uint64_t ram_bytes_remaining(void)
{
    return ram_save_remaining() * TARGET_PAGE_SIZE;
}

uint64_t ram_bytes_transferred(void)
{
    return bytes_transferred;
}

uint64_t ram_bytes_total(void)
{
    RAMBlock *block;
    uint64_t total = 0;

    QTAILQ_FOREACH(block, &ram_list.blocks, next)
        total += block->length;

    return total;
}

void free_xbzrle_decoded_buf(void)
{
    g_free(xbzrle_decoded_buf);
    xbzrle_decoded_buf = NULL;
}

static void migration_end(void)
{
    MigrationState *s = migrate_get_current();

    if (migration_bitmap) {
        memory_global_dirty_log_stop();
        g_free(migration_bitmap);
        migration_bitmap = NULL;
    }

    if (s->sentmap) {
        g_free(s->sentmap);
        s->sentmap = NULL;
    }

    XBZRLE_cache_lock();
    if (XBZRLE.cache) {
        cache_fini(XBZRLE.cache);
        g_free(XBZRLE.encoded_buf);
        g_free(XBZRLE.current_buf);
        XBZRLE.cache = NULL;
        XBZRLE.encoded_buf = NULL;
        XBZRLE.current_buf = NULL;
    }
    XBZRLE_cache_unlock();
}

static void ram_migration_cancel(void *opaque)
{
    migration_end();
}

static void reset_ram_globals(void)
{
    last_seen_block = NULL;
    last_sent_block = NULL;
    last_offset = 0;
    last_version = ram_list.version;
    ram_bulk_stage = true;
    last_was_from_queue = false;
}

#define MAX_WAIT 50 /* ms, half buffered_file limit */

/*
 * 'expected' is the value you expect the bitmap mostly to be full
 * of and it won't bother printing lines that are all this value
 * if 'todump' is null the migration bitmap is dumped.
 */
void ram_debug_dump_bitmap(unsigned long *todump, bool expected)
{
    int64_t ram_pages = last_ram_offset() >> TARGET_PAGE_BITS;

    int64_t cur;
    int64_t linelen = 128l;
    char linebuf[129];

    if (!todump) {
        todump = migration_bitmap;
    }

    for (cur = 0; cur < ram_pages; cur += linelen) {
        int64_t curb;
        bool found = false;
        /*
         * Last line; catch the case where the line length
         * is longer than remaining ram
         */
        if (cur+linelen > ram_pages) {
            linelen = ram_pages - cur;
        }
        for (curb = 0; curb < linelen; curb++) {
            bool thisbit = test_bit(cur+curb, todump);
            linebuf[curb] = thisbit ? '1' : '.';
            found |= (thisbit ^ expected);
        }
        if (found) {
            linebuf[curb] = '\0';
            fprintf(stderr,  "0x%08" PRIx64 " : %s\n", cur, linebuf);
        }
    }
}

/* **** functions for postcopy ***** */

/*
 * A helper to get 32 bits from a bit map; trivial for HOST_LONG_BITS=32
 * messier for 64; the bitmaps are actually long's that are 32 or 64bit
 */
static uint32_t get_32bits_map(unsigned long *map, int64_t start)
{
#if HOST_LONG_BITS == 64
    uint64_t tmp64;

    tmp64 = map[start / 64];
    return (start & 32) ? (tmp64 >> 32) : (tmp64 & 0xffffffffu);
#elif HOST_LONG_BITS == 32
    /*
     * Irrespective of host endianness, sentmap[n] is for pages earlier
     * than sentmap[n+1] so we can't just cast up
     */
    return map[start / 32];
#else
#error "Host long other than 64/32 not supported"
#endif
}

/*
 * A helper to put 32 bits into a bit map; trivial for HOST_LONG_BITS=32
 * messier for 64; the bitmaps are actually long's that are 32 or 64bit
 */
static void put_32bits_map(unsigned long *map, int64_t start,
                           uint32_t v)
{
#if HOST_LONG_BITS == 64
    uint64_t tmp64 = v;
    uint64_t mask = 0xffffffffu;

    if (start & 32) {
        tmp64 = tmp64 << 32;
        mask =  mask << 32;
    }

    map[start / 64] = (map[start / 64] & ~mask) | tmp64;
#elif HOST_LONG_BITS == 32
    /*
     * Irrespective of host endianness, sentmap[n] is for pages earlier
     * than sentmap[n+1] so we can't just cast up
     */
    map[start / 32] = v;
#else
#error "Host long other than 64/32 not supported"
#endif
}

/*
 * When working on 32bit chunks of a bitmap where the only valid section
 * is between start..end (inclusive), generate a mask with only those
 * valid bits set for the current 32bit word within that bitmask.
 */
static int make_32bit_mask(unsigned long start, unsigned long end,
                           unsigned long cur32)
{
    unsigned long first32, last32;
    uint32_t mask = ~(uint32_t)0;
    first32 = start / 32;
    last32 = end / 32;

    if ((cur32 == first32) && (start & 31)) {
        /* e.g. (start & 31) = 3
         *         1 << .    -> 2^3
         *         . - 1     -> 2^3 - 1 i.e. mask 2..0
         *         ~.        -> mask 31..3
         */
        mask &= ~((((uint32_t)1) << (start & 31)) - 1);
    }

    if ((cur32 == last32) && ((end & 31) != 31)) {
        /* e.g. (end & 31) = 3
         *            .   +1 -> 4
         *         1 << .    -> 2^4
         *         . -1      -> 2^4 - 1
         *                   = mask set 3..0
         */
        mask &= (((uint32_t)1) << ((end & 31) + 1)) - 1;
    }

    return mask;
}

/*
 * Callback from ram_postcopy_each_ram_discard for each RAMBlock
 * start,end: Indexes into the bitmap for the first and last bit
 *            representing the named block
 */
static int pc_send_discard_bm_ram(MigrationState *ms,
                                  PostcopyDiscardState *pds,
                                  unsigned long start, unsigned long end)
{
    /*
     * There is no guarantee that start, end are on convenient 32bit multiples
     * (We always send 32bit chunks over the wire, irrespective of long size)
     */
    unsigned long first32, last32, cur32;
    first32 = start / 32;
    last32 = end / 32;

    for (cur32 = first32; cur32 <= last32; cur32++) {
        /* Deal with start/end not on alignment */
        uint32_t mask = make_32bit_mask(start, end, cur32);

        uint32_t data = get_32bits_map(ms->sentmap, cur32 * 32);
        data &= mask;

        if (data) {
            postcopy_discard_send_chunk(ms, pds, (cur32-first32) * 32, data);
        }
    }

    return 0;
}

/*
 * Utility for the outgoing postcopy code.
 *   Calls postcopy_send_discard_bm_ram for each RAMBlock
 *   passing it bitmap indexes and name.
 * Returns: 0 on success
 * (qemu_ram_foreach_block ends up passing unscaled lengths
 *  which would mean postcopy code would have to deal with target page)
 */
static int pc_each_ram_discard(MigrationState *ms)
{
    struct RAMBlock *block;
    int ret;

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        unsigned long first = block->offset >> TARGET_PAGE_BITS;
        unsigned long last = (block->offset + (block->length-1))
                                >> TARGET_PAGE_BITS;
        PostcopyDiscardState *pds = postcopy_discard_send_init(ms,
                                                               first & 31,
                                                               block->idstr);

        /*
         * Postcopy sends chunks of bitmap over the wire, but it
         * just needs indexes at this point, avoids it having
         * target page specific code.
         */
        ret = pc_send_discard_bm_ram(ms, pds, first, last);
        postcopy_discard_send_finish(ms, pds);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

/*
 * Utility for the outgoing postcopy code.
 *
 * Discard any partially sent host-page size chunks, mark any partially
 * dirty host-page size chunks as all dirty.
 *
 * Returns: 0 on success
 */
static int postcopy_chunk_hostpages(MigrationState *ms)
{
    struct RAMBlock *block;
    unsigned int host_bits = sysconf(_SC_PAGESIZE) / TARGET_PAGE_SIZE;
    uint32_t host_mask;

    /* Should be a power of 2 */
    assert(host_bits && !(host_bits & (host_bits - 1)));
    /*
     * If the host_bits isn't a division of 32 (the minimum long size)
     * then the code gets a lot more complex; disallow for now
     * (I'm not aware of a system where it's true anyway)
     */
    assert((32 % host_bits) == 0);

    /* A mask, starting at bit 0, containing host_bits continuous set bits */
    host_mask =  (1u << host_bits) - 1;


    if (host_bits == 1) {
        /* Easy case - TPS==HPS - nothing to be done */
        return 0;
    }

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        unsigned long first32, last32, cur32;
        unsigned long first = block->offset >> TARGET_PAGE_BITS;
        unsigned long last = (block->offset + (block->length-1))
                                >> TARGET_PAGE_BITS;
        PostcopyDiscardState *pds = postcopy_discard_send_init(ms,
                                                               first & 31,
                                                               block->idstr);

        first32 = first / 32;
        last32 = last / 32;
        for (cur32 = first32; cur32 <= last32; cur32++) {
            unsigned int current_hp;
            /* Deal with start/end not on alignment */
            uint32_t mask = make_32bit_mask(first, last, cur32);

            /* a chunk of sent pages */
            uint32_t sdata = get_32bits_map(ms->sentmap, cur32 * 32);
            /* a chunk of dirty pages */
            uint32_t ddata = get_32bits_map(migration_bitmap, cur32 * 32);
            uint32_t discard = 0;
            uint32_t redirty = 0;
            sdata &= mask;
            ddata &= mask;

            for (current_hp = 0; current_hp < 32; current_hp += host_bits) {
                uint32_t host_sent = (sdata >> current_hp) & host_mask;
                uint32_t host_dirty = (ddata >> current_hp) & host_mask;

                if (host_sent && (host_sent != host_mask)) {
                    /* Partially sent host page */
                    redirty |= host_mask << current_hp;
                    discard |= host_mask << current_hp;

                } else if (host_dirty && (host_dirty != host_mask)) {
                    /* Partially dirty host page */
                    redirty |= host_mask << current_hp;
                }
            }
            if (discard) {
                /* Tell the destination to discard these pages */
                postcopy_discard_send_chunk(ms, pds, (cur32-first32) * 32,
                                            discard);
                /* And clear them in the sent data structure */
                sdata = get_32bits_map(ms->sentmap, cur32 * 32);
                put_32bits_map(ms->sentmap, cur32 * 32, sdata & ~discard);
            }
            if (redirty) {
                /*
                 * Reread original dirty bits and OR in ones we clear; we
                 * must reread since we might be at the start or end of
                 * a RAMBlock that the original 'mask' discarded some
                 * bits from
                */
                ddata = get_32bits_map(migration_bitmap, cur32 * 32);
                put_32bits_map(migration_bitmap, cur32 * 32,
                           ddata | redirty);
                /* Inc the count of dirty pages */
                migration_dirty_pages += ctpop32(redirty - (ddata & redirty));
            }
        }

        postcopy_discard_send_finish(ms, pds);
    }
    /* Easiest way to make sure we don't resume in the middle of a host-page */
    last_seen_block = NULL;
    last_sent_block = NULL;

    return 0;
}

/*
 * Transmit the set of pages to be discarded after precopy to the target
 * these are pages that have been sent previously but have been dirtied
 * Hopefully this is pretty sparse
 */
int ram_postcopy_send_discard_bitmap(MigrationState *ms)
{
    int ret;

    /* This should be our last sync, the src is now paused */
    migration_bitmap_sync();

    /* Deal with TPS != HPS */
    ret = postcopy_chunk_hostpages(ms);
    if (ret) {
        return ret;
    }

    /*
     * Update the sentmap to be  sentmap&=dirty
     */
    bitmap_and(ms->sentmap, ms->sentmap, migration_bitmap,
               last_ram_offset() >> TARGET_PAGE_BITS);


    DPRINTF("Dumping merged sentmap");
#ifdef DEBUG_POSTCOPY
    ram_debug_dump_bitmap(ms->sentmap, false);
#endif

    return pc_each_ram_discard(ms);
}

/*
 * At the start of the postcopy phase of migration, any now-dirty
 * precopied pages are discarded.
 *
 * start..end is an inclusive range of bits indexed in the source
 *    VMs bitmap for this RAMBlock, source_target_page_bits tells
 *    us what one of those bits represents.
 *
 * start/end are offsets from the start of the bitmap for RAMBlock 'block_name'
 *
 * Returns 0 on success.
 */
int ram_discard_range(MigrationIncomingState *mis,
                      const char *block_name,
                      uint64_t start, uint64_t end)
{
    assert(end >= start);

    RAMBlock *rb = ram_find_block(block_name);

    if (!rb) {
        error_report("ram_discard_range: Failed to find block '%s'",
                     block_name);
        return -1;
    }

    uint64_t index_offset = rb->offset >> TARGET_PAGE_BITS;
    postcopy_pmi_discard_range(mis, start + index_offset, (end - start) + 1);

    /* +1 gives the byte after the end of the last page to be discarded */
    ram_addr_t end_offset = (end+1) << TARGET_PAGE_BITS;
    uint8_t *host_startaddr = rb->host + (start << TARGET_PAGE_BITS);
    uint8_t *host_endaddr;

    if (end_offset <= rb->length) {
        host_endaddr   = rb->host + (end_offset-1);
        return postcopy_ram_discard_range(mis, host_startaddr, host_endaddr);
    } else {
        error_report("ram_discard_range: Overrun block '%s' (%" PRIu64
                     "/%" PRIu64 "/%zu)",
                     block_name, start, end, rb->length);
        return -1;
    }
}

static int ram_save_setup(QEMUFile *f, void *opaque)
{
    RAMBlock *block;
    int64_t ram_bitmap_pages; /* Size of bitmap in pages, including gaps */

    mig_throttle_on = false;
    dirty_rate_high_cnt = 0;
    bitmap_sync_count = 0;

    if (migrate_use_xbzrle()) {
        XBZRLE_cache_lock();
        XBZRLE.cache = cache_init(migrate_xbzrle_cache_size() /
                                  TARGET_PAGE_SIZE,
                                  TARGET_PAGE_SIZE);
        if (!XBZRLE.cache) {
            XBZRLE_cache_unlock();
            error_report("Error creating cache");
            return -1;
        }
        XBZRLE_cache_unlock();

        /* We prefer not to abort if there is no memory */
        XBZRLE.encoded_buf = g_try_malloc0(TARGET_PAGE_SIZE);
        if (!XBZRLE.encoded_buf) {
            error_report("Error allocating encoded_buf");
            return -1;
        }

        XBZRLE.current_buf = g_try_malloc(TARGET_PAGE_SIZE);
        if (!XBZRLE.current_buf) {
            error_report("Error allocating current_buf");
            g_free(XBZRLE.encoded_buf);
            XBZRLE.encoded_buf = NULL;
            return -1;
        }

        acct_clear();
    }
    qemu_mutex_lock_iothread();
    qemu_mutex_lock_ramlist();
    bytes_transferred = 0;
    reset_ram_globals();

    ram_bitmap_pages = last_ram_offset() >> TARGET_PAGE_BITS;
    migration_bitmap = bitmap_new(ram_bitmap_pages);
    bitmap_set(migration_bitmap, 0, ram_bitmap_pages);

    if (migrate_postcopy_ram()) {
        MigrationState *s = migrate_get_current();
        s->sentmap = bitmap_new(ram_bitmap_pages);
        bitmap_clear(s->sentmap, 0, ram_bitmap_pages);
    }

    /*
     * Count the total number of pages used by ram blocks not including any
     * gaps due to alignment or unplugs.
     */
    migration_dirty_pages = 0;
    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        uint64_t block_pages;

        block_pages = block->length >> TARGET_PAGE_BITS;
        migration_dirty_pages += block_pages;
    }

    memory_global_dirty_log_start();
    migration_bitmap_sync();
    qemu_mutex_unlock_iothread();

    qemu_put_be64(f, ram_bytes_total() | RAM_SAVE_FLAG_MEM_SIZE);

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        qemu_put_byte(f, strlen(block->idstr));
        qemu_put_buffer(f, (uint8_t *)block->idstr, strlen(block->idstr));
        qemu_put_be64(f, block->length);
    }

    qemu_mutex_unlock_ramlist();

    ram_control_before_iterate(f, RAM_CONTROL_SETUP);
    ram_control_after_iterate(f, RAM_CONTROL_SETUP);

    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);

    return 0;
}

static int ram_save_iterate(QEMUFile *f, void *opaque)
{
    int ret;
    int i;
    int64_t t0;
    int total_sent = 0;

    qemu_mutex_lock_ramlist();

    if (ram_list.version != last_version) {
        reset_ram_globals();
    }

    ram_control_before_iterate(f, RAM_CONTROL_ROUND);

    t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    i = 0;
    while ((ret = qemu_file_rate_limit(f)) == 0) {
        int bytes_sent;

        bytes_sent = ram_find_and_save_block(f, false);
        /* no more blocks to sent */
        if (bytes_sent == 0) {
            break;
        }
        total_sent += bytes_sent;
        acct_info.iterations++;
        check_guest_throttling();
        /* we want to check in the 1st loop, just in case it was the 1st time
           and we had to sync the dirty bitmap.
           qemu_get_clock_ns() is a bit expensive, so we only check each some
           iterations
        */
        if ((i & 63) == 0) {
            uint64_t t1 = (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - t0) / 1000000;
            if (t1 > MAX_WAIT) {
                DPRINTF("big wait: %" PRIu64 " milliseconds, %d iterations\n",
                        t1, i);
                break;
            }
        }
        i++;
    }

    qemu_mutex_unlock_ramlist();

    /*
     * Must occur before EOS (or any QEMUFile operation)
     * because of RDMA protocol.
     */
    ram_control_after_iterate(f, RAM_CONTROL_ROUND);

    bytes_transferred += total_sent;

    /*
     * Do not count these 8 bytes into total_sent, so that we can
     * return 0 if no page had been dirtied.
     */
    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);
    bytes_transferred += 8;

    ret = qemu_file_get_error(f);
    if (ret < 0) {
        return ret;
    }

    return total_sent;
}

static int ram_save_complete(QEMUFile *f, void *opaque)
{
    qemu_mutex_lock_ramlist();

    if (!migration_postcopy_phase(migrate_get_current())) {
        migration_bitmap_sync();
    }

    ram_control_before_iterate(f, RAM_CONTROL_FINISH);

    /* try transferring iterative blocks of memory */

    /* flush all remaining blocks regardless of rate limiting */
    while (true) {
        int bytes_sent;

        bytes_sent = ram_find_and_save_block(f, true);
        /* no more blocks to sent */
        if (bytes_sent == 0) {
            break;
        }
        bytes_transferred += bytes_sent;
    }

    ram_control_after_iterate(f, RAM_CONTROL_FINISH);
    migration_end();

    qemu_mutex_unlock_ramlist();
    qemu_put_be64(f, RAM_SAVE_FLAG_EOS);

    return 0;
}

static uint64_t ram_save_pending(QEMUFile *f, void *opaque, uint64_t max_size)
{
    uint64_t remaining_size;

    remaining_size = ram_save_remaining() * TARGET_PAGE_SIZE;

    if (!migration_postcopy_phase(migrate_get_current()) &&
        remaining_size < max_size) {
        qemu_mutex_lock_iothread();
        migration_bitmap_sync();
        qemu_mutex_unlock_iothread();
        remaining_size = ram_save_remaining() * TARGET_PAGE_SIZE;
    }
    return remaining_size;
}

static int load_xbzrle(QEMUFile *f, ram_addr_t addr, void *host)
{
    unsigned int xh_len;
    int xh_flags;

    if (!xbzrle_decoded_buf) {
        xbzrle_decoded_buf = g_malloc(TARGET_PAGE_SIZE);
    }

    /* extract RLE header */
    xh_flags = qemu_get_byte(f);
    xh_len = qemu_get_be16(f);

    if (xh_flags != ENCODING_FLAG_XBZRLE) {
        error_report("Failed to load XBZRLE page - wrong compression!");
        return -1;
    }

    if (xh_len > TARGET_PAGE_SIZE) {
        error_report("Failed to load XBZRLE page - len overflow!");
        return -1;
    }
    /* load data and decode */
    qemu_get_buffer(f, xbzrle_decoded_buf, xh_len);

    /* decode RLE */
    if (xbzrle_decode_buffer(xbzrle_decoded_buf, xh_len, host,
                             TARGET_PAGE_SIZE) == -1) {
        error_report("Failed to load XBZRLE page - decode error!");
        return -1;
    }

    return 0;
}

/*
 * Read a RAMBlock ID from the stream f, find the host address of the
 * start of that block and add on 'offset'
 *
 * f: Stream to read from
 * mis: MigrationIncomingState
 * offset: Offset within the block
 * flags: Page flags (mostly to see if it's a continuation of previous block)
 * rb: Pointer to RAMBlock* that gets filled in with the RB we find
 */
static inline void *host_from_stream_offset(QEMUFile *f,
                                            MigrationIncomingState *mis,
                                            ram_addr_t offset,
                                            int flags, RAMBlock **rb)
{
    static RAMBlock *block = NULL;
    char id[256];
    uint8_t len;

    if (flags & RAM_SAVE_FLAG_CONTINUE) {
        if (!block) {
            error_report("Ack, bad migration stream!");
            return NULL;
        }
        if (rb) {
            *rb = block;
        }

        goto gotit;
    }

    len = qemu_get_byte(f);
    qemu_get_buffer(f, (uint8_t *)id, len);
    id[len] = 0;

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        if (!strncmp(id, block->idstr, sizeof(id))) {
            if (rb) {
                *rb = block;
            }
            goto gotit;
        }
    }

    error_report("Can't find block %s!", id);
    return NULL;

gotit:
    postcopy_hook_early_receive(mis,
        (offset + (*rb)->offset) >> TARGET_PAGE_BITS);
    return memory_region_get_ram_ptr(block->mr) + offset;

}

/*
 * If a page (or a whole RDMA chunk) has been
 * determined to be zero, then zap it.
 */
void ram_handle_compressed(void *host, uint8_t ch, uint64_t size)
{
    if (ch != 0 || !is_zero_range(host, size)) {
        memset(host, ch, size);
    }
}

/*
 * Allocate data structures etc needed by incoming migration with postcopy-ram
 * postcopy-ram's similarly names postcopy_ram_incoming_init does the work
 */
int ram_postcopy_incoming_init(MigrationIncomingState *mis)
{
    size_t ram_pages = last_ram_offset() >> TARGET_PAGE_BITS;

    return postcopy_ram_incoming_init(mis, ram_pages);
}

static int ram_load(QEMUFile *f, void *opaque, int version_id)
{
    ram_addr_t addr;
    int flags, ret = 0;
    static uint64_t seq_iter;
    /*
     * System is running in postcopy mode, page inserts to host memory must be
     * atomic
     */
    MigrationIncomingState *mis = migration_incoming_get_current();
    bool postcopy_running = mis->postcopy_ram_state >=
                            POSTCOPY_RAM_INCOMING_LISTENING;

    seq_iter++;

    if (version_id != 4) {
        ret = -EINVAL;
    }

    while (!ret) {
        RAMBlock *rb = 0; /* =0 needed to silence compiler */
        addr = qemu_get_be64(f);

        flags = addr & ~TARGET_PAGE_MASK;
        addr &= TARGET_PAGE_MASK;

        if (flags & RAM_SAVE_FLAG_MEM_SIZE) {
            /* Synchronize RAM block list */
            char id[256];
            ram_addr_t length;
            ram_addr_t total_ram_bytes = addr;

            while (total_ram_bytes) {
                RAMBlock *block;
                uint8_t len;

                len = qemu_get_byte(f);
                qemu_get_buffer(f, (uint8_t *)id, len);
                id[len] = 0;
                length = qemu_get_be64(f);

                QTAILQ_FOREACH(block, &ram_list.blocks, next) {
                    if (!strncmp(id, block->idstr, sizeof(id))) {
                        if (block->length != length) {
                            error_report("Length mismatch: %s: 0x" RAM_ADDR_FMT
                                         " in != 0x" RAM_ADDR_FMT, id, length,
                                         block->length);
                            ret =  -EINVAL;
                        }
                        break;
                    }
                }

                if (!block) {
                    error_report("Unknown ramblock \"%s\", cannot "
                                 "accept migration", id);
                    ret = -EINVAL;
                }
                if (ret) {
                    break;
                }

                total_ram_bytes -= length;
            }
        } else if (flags & RAM_SAVE_FLAG_COMPRESS) {
            void *host;
            uint8_t ch;

            host = host_from_stream_offset(f, mis, addr, flags, &rb);
            if (!host) {
                error_report("Illegal RAM offset " RAM_ADDR_FMT, addr);
                ret = -EINVAL;
                break;
            }

            ch = qemu_get_byte(f);
            if (!postcopy_running) {
                ram_handle_compressed(host, ch, TARGET_PAGE_SIZE);
            } else {
                if (!ch) {
                    ret = postcopy_place_zero_page(mis, host,
                              (addr + rb->offset) >> TARGET_PAGE_BITS);
                } else {
                    void *tmp;
                    tmp = postcopy_get_tmp_page(mis, (addr + rb->offset) >>
                                                      TARGET_PAGE_BITS);

                    if (!tmp) {
                        return -ENOMEM;
                    }
                    memset(tmp, ch, TARGET_PAGE_SIZE);
                    ret = postcopy_place_page(mis, host, tmp,
                              (addr + rb->offset) >> TARGET_PAGE_BITS);
                }
                if (ret) {
                    error_report("ram_load: Failure in postcopy compress @"
                                 "%zx/%p;%s+%zx",
                                 addr, host, rb->idstr, rb->offset);
                    return ret;
                }
            }
        } else if (flags & RAM_SAVE_FLAG_PAGE) {
            void *host;

            host = host_from_stream_offset(f, mis, addr, flags, &rb);
            if (!host) {
                error_report("Illegal RAM offset " RAM_ADDR_FMT, addr);
                ret = -EINVAL;
                break;
            }

            if (!postcopy_running) {
                qemu_get_buffer(f, host, TARGET_PAGE_SIZE);
            } else {
                void *tmp = postcopy_get_tmp_page(mis, (addr + rb->offset) >>
                                                        TARGET_PAGE_BITS);

                if (!tmp) {
                    return -ENOMEM;
                }
                qemu_get_buffer(f, tmp, TARGET_PAGE_SIZE);
                ret = postcopy_place_page(mis, host, tmp,
                          (addr + rb->offset) >> TARGET_PAGE_BITS);
                if (ret) {
                    error_report("ram_load: Failure in postcopy simple"
                                 "@%zx/%p;%s+%zx",
                                 addr, host, rb->idstr, rb->offset);
                    return ret;
                }
            }
        } else if (flags & RAM_SAVE_FLAG_XBZRLE) {
            if (postcopy_running) {
                error_report("XBZRLE RAM block in postcopy mode @%zx\n", addr);
                return -EINVAL;
            }
            void *host = host_from_stream_offset(f, mis, addr, flags, &rb);
            if (!host) {
                error_report("Illegal RAM offset " RAM_ADDR_FMT, addr);
                ret = -EINVAL;
                break;
            }

            if (load_xbzrle(f, addr, host) < 0) {
                error_report("Failed to decompress XBZRLE page at "
                             RAM_ADDR_FMT, addr);
                ret = -EINVAL;
                break;
            }
        } else if (flags & RAM_SAVE_FLAG_HOOK) {
            ram_control_load_hook(f, flags);
        } else if (flags & RAM_SAVE_FLAG_EOS) {
            /* normal exit */
            break;
        } else {
            error_report("Unknown migration flags: %#x", flags);
            ret = -EINVAL;
            break;
        }
        ret = qemu_file_get_error(f);
    }

    DPRINTF("Completed load of VM with exit code %d seq iteration "
            "%" PRIu64 "\n", ret, seq_iter);
    return ret;
}

/* RAM's always up for postcopying */
static bool ram_can_postcopy(void *opaque)
{
    return true;
}

static SaveVMHandlers savevm_ram_handlers = {
    .save_live_setup = ram_save_setup,
    .save_live_iterate = ram_save_iterate,
    .save_live_complete = ram_save_complete,
    .save_live_pending = ram_save_pending,
    .load_state = ram_load,
    .cancel = ram_migration_cancel,
    .can_postcopy = ram_can_postcopy,
};

void ram_mig_init(void)
{
    qemu_mutex_init(&XBZRLE.lock);
    register_savevm_live(NULL, "ram", 0, 4, &savevm_ram_handlers, NULL);
}

struct soundhw {
    const char *name;
    const char *descr;
    int enabled;
    int isa;
    union {
        int (*init_isa) (ISABus *bus);
        int (*init_pci) (PCIBus *bus);
    } init;
};

static struct soundhw soundhw[9];
static int soundhw_count;

void isa_register_soundhw(const char *name, const char *descr,
                          int (*init_isa)(ISABus *bus))
{
    assert(soundhw_count < ARRAY_SIZE(soundhw) - 1);
    soundhw[soundhw_count].name = name;
    soundhw[soundhw_count].descr = descr;
    soundhw[soundhw_count].isa = 1;
    soundhw[soundhw_count].init.init_isa = init_isa;
    soundhw_count++;
}

void pci_register_soundhw(const char *name, const char *descr,
                          int (*init_pci)(PCIBus *bus))
{
    assert(soundhw_count < ARRAY_SIZE(soundhw) - 1);
    soundhw[soundhw_count].name = name;
    soundhw[soundhw_count].descr = descr;
    soundhw[soundhw_count].isa = 0;
    soundhw[soundhw_count].init.init_pci = init_pci;
    soundhw_count++;
}

void select_soundhw(const char *optarg)
{
    struct soundhw *c;

    if (is_help_option(optarg)) {
    show_valid_cards:

        if (soundhw_count) {
             printf("Valid sound card names (comma separated):\n");
             for (c = soundhw; c->name; ++c) {
                 printf ("%-11s %s\n", c->name, c->descr);
             }
             printf("\n-soundhw all will enable all of the above\n");
        } else {
             printf("Machine has no user-selectable audio hardware "
                    "(it may or may not have always-present audio hardware).\n");
        }
        exit(!is_help_option(optarg));
    }
    else {
        size_t l;
        const char *p;
        char *e;
        int bad_card = 0;

        if (!strcmp(optarg, "all")) {
            for (c = soundhw; c->name; ++c) {
                c->enabled = 1;
            }
            return;
        }

        p = optarg;
        while (*p) {
            e = strchr(p, ',');
            l = !e ? strlen(p) : (size_t) (e - p);

            for (c = soundhw; c->name; ++c) {
                if (!strncmp(c->name, p, l) && !c->name[l]) {
                    c->enabled = 1;
                    break;
                }
            }

            if (!c->name) {
                if (l > 80) {
                    error_report("Unknown sound card name (too big to show)");
                }
                else {
                    error_report("Unknown sound card name `%.*s'",
                                 (int) l, p);
                }
                bad_card = 1;
            }
            p += l + (e != NULL);
        }

        if (bad_card) {
            goto show_valid_cards;
        }
    }
}

void audio_init(void)
{
    struct soundhw *c;
    ISABus *isa_bus = (ISABus *) object_resolve_path_type("", TYPE_ISA_BUS, NULL);
    PCIBus *pci_bus = (PCIBus *) object_resolve_path_type("", TYPE_PCI_BUS, NULL);

    for (c = soundhw; c->name; ++c) {
        if (c->enabled) {
            if (c->isa) {
                if (!isa_bus) {
                    error_report("ISA bus not available for %s", c->name);
                    exit(1);
                }
                c->init.init_isa(isa_bus);
            } else {
                if (!pci_bus) {
                    error_report("PCI bus not available for %s", c->name);
                    exit(1);
                }
                c->init.init_pci(pci_bus);
            }
        }
    }
}

int qemu_uuid_parse(const char *str, uint8_t *uuid)
{
    int ret;

    if (strlen(str) != 36) {
        return -1;
    }

    ret = sscanf(str, UUID_FMT, &uuid[0], &uuid[1], &uuid[2], &uuid[3],
                 &uuid[4], &uuid[5], &uuid[6], &uuid[7], &uuid[8], &uuid[9],
                 &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14],
                 &uuid[15]);

    if (ret != 16) {
        return -1;
    }
    return 0;
}

void do_acpitable_option(const QemuOpts *opts)
{
#ifdef TARGET_I386
    Error *err = NULL;

    acpi_table_add(opts, &err);
    if (err) {
        error_report("Wrong acpi table provided: %s",
                     error_get_pretty(err));
        error_free(err);
        exit(1);
    }
#endif
}

void do_smbios_option(QemuOpts *opts)
{
#ifdef TARGET_I386
    smbios_entry_add(opts);
#endif
}

void cpudef_init(void)
{
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file */
#endif
}

int tcg_available(void)
{
    return 1;
}

int kvm_available(void)
{
#ifdef CONFIG_KVM
    return 1;
#else
    return 0;
#endif
}

int xen_available(void)
{
#ifdef CONFIG_XEN
    return 1;
#else
    return 0;
#endif
}


TargetInfo *qmp_query_target(Error **errp)
{
    TargetInfo *info = g_malloc0(sizeof(*info));

    info->arch = g_strdup(TARGET_NAME);

    return info;
}

/* Stub function that's gets run on the vcpu when its brought out of the
   VM to run inside qemu via async_run_on_cpu()*/
static void mig_sleep_cpu(void *opq)
{
    qemu_mutex_unlock_iothread();
    g_usleep(30*1000);
    qemu_mutex_lock_iothread();
}

/* To reduce the dirty rate explicitly disallow the VCPUs from spending
   much time in the VM. The migration thread will try to catchup.
   Workload will experience a performance drop.
*/
static void mig_throttle_guest_down(void)
{
    CPUState *cpu;

    qemu_mutex_lock_iothread();
    CPU_FOREACH(cpu) {
        async_run_on_cpu(cpu, mig_sleep_cpu, NULL);
    }
    qemu_mutex_unlock_iothread();
}

static void check_guest_throttling(void)
{
    static int64_t t0;
    int64_t        t1;

    if (!mig_throttle_on) {
        return;
    }

    if (!t0)  {
        t0 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        return;
    }

    t1 = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    /* If it has been more than 40 ms since the last time the guest
     * was throttled then do it again.
     */
    if (40 < (t1-t0)/1000000) {
        mig_throttle_guest_down();
        t0 = t1;
    }
}
