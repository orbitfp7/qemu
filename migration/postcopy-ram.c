/*
 * Postcopy migration for RAM
 *
 * Copyright 2013-2015 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Dave Gilbert  <dgilbert@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

/*
 * Postcopy is a migration technique where the execution flips from the
 * source to the destination before all the data has been copied.
 */

#include <glib.h>
#include <stdio.h>
#include <unistd.h>

#include "qemu-common.h"
#include "migration/migration.h"
#include "migration/postcopy-ram.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "trace.h"

#define MAX_DISCARDS_PER_COMMAND 12

struct PostcopyDiscardState {
    const char *name;
    uint64_t offset; /* Bitmap entry for the 1st bit of this RAMBlock */
    uint16_t cur_entry;
    /*
     * Start and end address of a discard range; end_list points to the byte
     * after the end of the range.
     */
    uint64_t start_list[MAX_DISCARDS_PER_COMMAND];
    uint64_t   end_list[MAX_DISCARDS_PER_COMMAND];
    unsigned int nsentwords;
    unsigned int nsentcmds;
};

/* Postcopy needs to detect accesses to pages that haven't yet been copied
 * across, and efficiently map new pages in, the techniques for doing this
 * are target OS specific.
 */
#if defined(__linux__)

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <asm/types.h> /* for __u64 */
#endif

#if defined(__linux__) && defined(__NR_userfaultfd)
#include <linux/userfaultfd.h>

static bool ufd_version_check(int ufd)
{
    struct uffdio_api api_struct;
    uint64_t feature_mask;

    api_struct.api = UFFD_API;
    if (ioctl(ufd, UFFDIO_API, &api_struct)) {
        error_report("postcopy_ram_supported_by_host: UFFDIO_API failed: %s",
                     strerror(errno));
        return false;
    }

    feature_mask = (__u64)1 << _UFFDIO_REGISTER |
                   (__u64)1 << _UFFDIO_UNREGISTER;
    if ((api_struct.ioctls & feature_mask) != feature_mask) {
        error_report("Missing userfault features: %" PRIx64,
                     (uint64_t)(~api_struct.ioctls & feature_mask));
        return false;
    }

    return true;
}

bool postcopy_ram_supported_by_host(void)
{
    long pagesize = getpagesize();
    int ufd = -1;
    bool ret = false; /* Error unless we change it */
    void *testarea = NULL;
    struct uffdio_register reg_struct;
    struct uffdio_range range_struct;
    uint64_t feature_mask;

    if ((1ul << qemu_target_page_bits()) > pagesize) {
        error_report("Target page size bigger than host page size");
        goto out;
    }

    ufd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (ufd == -1) {
        error_report("%s: userfaultfd not available: %s", __func__,
                     strerror(errno));
        goto out;
    }

    /* Version and features check */
    if (!ufd_version_check(ufd)) {
        goto out;
    }

    /*
     *  We need to check that the ops we need are supported on anon memory
     *  To do that we need to register a chunk and see the flags that
     *  are returned.
     */
    testarea = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE |
                                    MAP_ANONYMOUS, -1, 0);
    if (testarea == MAP_FAILED) {
        error_report("%s: Failed to map test area: %s", __func__,
                     strerror(errno));
        goto out;
    }
    g_assert(((size_t)testarea & (pagesize-1)) == 0);

    reg_struct.range.start = (uintptr_t)testarea;
    reg_struct.range.len = pagesize;
    reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;

    if (ioctl(ufd, UFFDIO_REGISTER, &reg_struct)) {
        error_report("%s userfault register: %s", __func__, strerror(errno));
        goto out;
    }

    range_struct.start = (uintptr_t)testarea;
    range_struct.len = pagesize;
    if (ioctl(ufd, UFFDIO_UNREGISTER, &range_struct)) {
        error_report("%s userfault unregister: %s", __func__, strerror(errno));
        goto out;
    }

    feature_mask = (__u64)1 << _UFFDIO_WAKE |
                   (__u64)1 << _UFFDIO_COPY |
                   (__u64)1 << _UFFDIO_ZEROPAGE;
    if ((reg_struct.ioctls & feature_mask) != feature_mask) {
        error_report("Missing userfault map features: %" PRIx64,
                     (uint64_t)(~reg_struct.ioctls & feature_mask));
        goto out;
    }

    /* Success! */
    ret = true;
out:
    if (testarea) {
        munmap(testarea, pagesize);
    }
    if (ufd != -1) {
        close(ufd);
    }
    return ret;
}

/*
 * Discard the contents of memory start..end inclusive.
 * We can assume that if we've been called postcopy_ram_hosttest returned true
 */
int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end)
{
    trace_postcopy_ram_discard_range(start, end);
    if (madvise(start, (end-start)+1, MADV_DONTNEED)) {
        error_report("%s MADV_DONTNEED: %s", __func__, strerror(errno));
        return -1;
    }

    return 0;
}

#else
/* No target OS support, stubs just fail */

bool postcopy_ram_supported_by_host(void)
{
    error_report("%s: No OS support", __func__);
    return false;
}

int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end)
{
    assert(0);
}
#endif

/* ------------------------------------------------------------------------- */

/*
 * Called at the start of each RAMBlock by the bitmap code
 * 'offset' is the bitmap offset of the named RAMBlock in the migration
 * bitmap.
 * Returns a new PDS
 */
PostcopyDiscardState *postcopy_discard_send_init(MigrationState *ms,
                                                 unsigned long offset,
                                                 const char *name)
{
    PostcopyDiscardState *res = g_try_malloc(sizeof(PostcopyDiscardState));

    if (res) {
        res->name = name;
        res->cur_entry = 0;
        res->nsentwords = 0;
        res->nsentcmds = 0;
        res->offset = offset;
    }

    return res;
}

/*
 * Called by the bitmap code for each chunk to discard
 * May send a discard message, may just leave it queued to
 * be sent later
 * 'start' and 'end' describe an inclusive range of pages in the
 * migration bitmap in the RAM block passed to postcopy_discard_send_init
 */
void postcopy_discard_send_range(MigrationState *ms, PostcopyDiscardState *pds,
                                unsigned long start, unsigned long end)
{
    size_t tp_bits = qemu_target_page_bits();
    /* Convert to byte offsets within the RAM block */
    pds->start_list[pds->cur_entry] = (start - pds->offset) << tp_bits;
    pds->end_list[pds->cur_entry] = (1 + end - pds->offset) << tp_bits;
    pds->cur_entry++;
    pds->nsentwords++;

    if (pds->cur_entry == MAX_DISCARDS_PER_COMMAND) {
        /* Full set, ship it! */
        qemu_savevm_send_postcopy_ram_discard(ms->file, pds->name,
                                              pds->cur_entry,
                                              pds->start_list, pds->end_list);
        pds->nsentcmds++;
        pds->cur_entry = 0;
    }
}

/*
 * Called at the end of each RAMBlock by the bitmap code
 * Sends any outstanding discard messages, frees the PDS
 */
void postcopy_discard_send_finish(MigrationState *ms, PostcopyDiscardState *pds)
{
    /* Anything unsent? */
    if (pds->cur_entry) {
        qemu_savevm_send_postcopy_ram_discard(ms->file, pds->name,
                                              pds->cur_entry,
                                              pds->start_list, pds->end_list);
        pds->nsentcmds++;
    }

    trace_postcopy_discard_send_finish(pds->name, pds->nsentwords,
                                       pds->nsentcmds);

    g_free(pds);
}
