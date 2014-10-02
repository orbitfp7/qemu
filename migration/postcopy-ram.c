/*
 * Postcopy migration for RAM
 *
 * Copyright 2013-2014 Red Hat, Inc. and/or its affiliates
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
#include "qemu/bitmap.h"
#include "qemu/error-report.h"
#include "trace.h"

/* Postcopy needs to detect accesses to pages that haven't yet been copied
 * across, and efficiently map new pages in, the techniques for doing this
 * are target OS specific.
 */
#if defined(__linux__)

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <asm/types.h> /* for __u64 */
#include <linux/userfaultfd.h>

#ifdef HOST_X86_64
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif
#endif

#endif

#if defined(__linux__) && defined(__NR_userfaultfd)

/* ---------------------------------------------------------------------- */
/* Postcopy pagemap-inbound (pmi) - data structures that record the       */
/* state of each page used by the inbound postcopy                        */
/* It's a pair of bitmaps (of the same structure as the migration bitmaps)*/
/* holding one bit per target-page, although most operations work on host */
/* pages, the exception being a hook that receives incoming pages off the */
/* migration stream which come in a TP at a time, although the source     */
/* _should_ guarantee it sends a sequence of TPs representing HPs during  */
/* the postcopy phase, there is no such guarantee during precopy.  We     */
/* could boil this down to only holding one bit per-host page, but we lose*/
/* sanity checking that we really do get whole host-pages from the source.*/
__attribute__ (( unused )) /* Until later in patch series */
static void postcopy_pmi_init(MigrationIncomingState *mis, size_t ram_pages)
{
    unsigned int tpb = qemu_target_page_bits();
    unsigned long host_bits;

    qemu_mutex_init(&mis->postcopy_pmi.mutex);
    mis->postcopy_pmi.state0 = bitmap_new(ram_pages);
    mis->postcopy_pmi.state1 = bitmap_new(ram_pages);
    bitmap_clear(mis->postcopy_pmi.state0, 0, ram_pages);
    bitmap_clear(mis->postcopy_pmi.state1, 0, ram_pages);
    /*
     * Each bit in the map represents one 'target page' which is no bigger
     * than a host page but can be smaller.  It's useful to have some
     * convenience masks for later
     */

    /*
     * The number of bits one host page takes up in the bitmap
     * e.g. on a 64k host page, 4k Target page, host_bits=64/4=16
     */
    host_bits = getpagesize() / (1ul << tpb);
    assert(is_power_of_2(host_bits));

    mis->postcopy_pmi.host_bits = host_bits;

    if (host_bits < BITS_PER_LONG) {
        /* A mask starting at bit 0 containing host_bits continuous set bits */
        mis->postcopy_pmi.host_mask =  (1ul << host_bits) - 1;
    } else {
        /*
         * This is a host where the ratio between host and target pages is
         * bigger than the size of our longs, so we can't make a mask
         * but we are only losing sanity checking if we just check one long's
         * worth of bits.
         */
        mis->postcopy_pmi.host_mask = ~0l;
    }


    assert((ram_pages % host_bits) == 0);
}

void postcopy_pmi_destroy(MigrationIncomingState *mis)
{
    g_free(mis->postcopy_pmi.state0);
    mis->postcopy_pmi.state0 = NULL;
    g_free(mis->postcopy_pmi.state1);
    mis->postcopy_pmi.state1 = NULL;
    qemu_mutex_destroy(&mis->postcopy_pmi.mutex);
}

/*
 * Mark a set of pages in the PMI as being clear; this is used by the discard
 * at the start of postcopy, and before the postcopy stream starts.
 */
void postcopy_pmi_discard_range(MigrationIncomingState *mis,
                                size_t start, size_t npages)
{
    /* Clear to state 0 = missing */
    bitmap_clear(mis->postcopy_pmi.state0, start, npages);
    bitmap_clear(mis->postcopy_pmi.state1, start, npages);
}

/*
 * Test a host-page worth of bits in the map starting at bitmap_index
 * The bits should all be consistent
 */
static bool test_hpbits(MigrationIncomingState *mis,
                        size_t bitmap_index, unsigned long *map)
{
    long masked;

    assert((bitmap_index & (mis->postcopy_pmi.host_bits-1)) == 0);

    masked = (map[BIT_WORD(bitmap_index)] >>
               (bitmap_index % BITS_PER_LONG)) &
             mis->postcopy_pmi.host_mask;

    assert((masked == 0) || (masked == mis->postcopy_pmi.host_mask));
    return !!masked;
}

/*
 * Set host-page worth of bits in the map starting at bitmap_index
 * to the given state
 */
static void set_hp(MigrationIncomingState *mis,
                   size_t bitmap_index, PostcopyPMIState state)
{
    long shifted_mask = mis->postcopy_pmi.host_mask <<
                        (bitmap_index % BITS_PER_LONG);

    assert((bitmap_index & (mis->postcopy_pmi.host_bits-1)) == 0);

    if (state & 1) {
        mis->postcopy_pmi.state0[BIT_WORD(bitmap_index)] |= shifted_mask;
    } else {
        mis->postcopy_pmi.state0[BIT_WORD(bitmap_index)] &= ~shifted_mask;
    }
    if (state & 2) {
        mis->postcopy_pmi.state1[BIT_WORD(bitmap_index)] |= shifted_mask;
    } else {
        mis->postcopy_pmi.state1[BIT_WORD(bitmap_index)] &= ~shifted_mask;
    }
}

/*
 * Retrieve the state of the given page
 * Note: This version for use by callers already holding the lock
 */
static PostcopyPMIState postcopy_pmi_get_state_nolock(
                            MigrationIncomingState *mis,
                            size_t bitmap_index)
{
    bool b0, b1;

    b0 = test_hpbits(mis, bitmap_index, mis->postcopy_pmi.state0);
    b1 = test_hpbits(mis, bitmap_index, mis->postcopy_pmi.state1);

    return (b0 ? 1 : 0) + (b1 ? 2 : 0);
}

/* Retrieve the state of the given page */
__attribute__ (( unused )) /* Until later in patch series */
static PostcopyPMIState postcopy_pmi_get_state(MigrationIncomingState *mis,
                                               size_t bitmap_index)
{
    PostcopyPMIState ret;
    qemu_mutex_lock(&mis->postcopy_pmi.mutex);
    ret = postcopy_pmi_get_state_nolock(mis, bitmap_index);
    qemu_mutex_unlock(&mis->postcopy_pmi.mutex);

    return ret;
}

/*
 * Set the page state to the given state if the previous state was as expected
 * Return the actual previous state.
 */
__attribute__ (( unused )) /* Until later in patch series */
static PostcopyPMIState postcopy_pmi_change_state(MigrationIncomingState *mis,
                                           size_t bitmap_index,
                                           PostcopyPMIState expected_state,
                                           PostcopyPMIState new_state)
{
    PostcopyPMIState old_state;

    qemu_mutex_lock(&mis->postcopy_pmi.mutex);
    old_state = postcopy_pmi_get_state_nolock(mis, bitmap_index);

    if (old_state == expected_state) {
        switch (new_state) {
        case POSTCOPY_PMI_MISSING:
            assert(0); /* This shouldn't happen - use discard_range */
            break;

        case POSTCOPY_PMI_REQUESTED:
            assert(old_state == POSTCOPY_PMI_MISSING);
            /* missing -> requested */
            set_hp(mis, bitmap_index, POSTCOPY_PMI_REQUESTED);
            break;

        case POSTCOPY_PMI_RECEIVED:
            assert(old_state == POSTCOPY_PMI_MISSING ||
                   old_state == POSTCOPY_PMI_REQUESTED);
            /* -> received */
            set_hp(mis, bitmap_index, POSTCOPY_PMI_RECEIVED);
            break;
        }
    }

    qemu_mutex_unlock(&mis->postcopy_pmi.mutex);
    return old_state;
}

/*
 * Useful when debugging postcopy, although if it failed early the
 * received map can be quite sparse and thus big when dumped.
 */
void postcopy_pmi_dump(MigrationIncomingState *mis)
{
    fprintf(stderr, "postcopy_pmi_dump: bit 0\n");
    ram_debug_dump_bitmap(mis->postcopy_pmi.state0, false);
    fprintf(stderr, "postcopy_pmi_dump: bit 1\n");
    ram_debug_dump_bitmap(mis->postcopy_pmi.state1, true);
    fprintf(stderr, "postcopy_pmi_dump: end\n");
}

/* Called by ram_load prior to mapping the page */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index)
{
    if (mis->postcopy_state == POSTCOPY_INCOMING_ADVISE) {
        /*
         * If we're in precopy-advise mode we need to track received pages even
         * though we don't need to place pages atomically yet.
         * In advise mode there's only a single thread, so don't need locks
         */
        set_bit(bitmap_index, mis->postcopy_pmi.state1); /* 2=received */
    }
}

static bool ufd_version_check(int ufd)
{
    struct uffdio_api api_struct;
    uint64_t feature_mask;

    api_struct.api = UFFD_API;
    if (ioctl(ufd, UFFDIO_API, &api_struct)) {
        perror("postcopy_ram_supported_by_host: UFFDIO_API failed");
        return false;
    }

    feature_mask = (__u64)1 << _UFFDIO_REGISTER |
                   (__u64)1 << _UFFDIO_UNREGISTER;
    if ((api_struct.ioctls & feature_mask) != feature_mask) {
        error_report("Missing userfault features: %" PRIu64,
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
        /* The PMI code doesn't yet deal with TPS>HPS */
        error_report("Target page size bigger than host page size");
        goto out;
    }

    ufd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (ufd == -1) {
        perror("postcopy_ram_supported_by_host: userfaultfd not available");
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
    if (!testarea) {
        perror("postcopy_ram_supported_by_host: Failed to map test area");
        goto out;
    }
    g_assert(((size_t)testarea & (pagesize-1)) == 0);

    reg_struct.range.start = (uint64_t)(uintptr_t)testarea;
    reg_struct.range.len = (uint64_t)pagesize;
    reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;

    if (ioctl(ufd, UFFDIO_REGISTER, &reg_struct)) {
        perror("postcopy_ram_supported_by_host userfault register");
        goto out;
    }

    range_struct.start = (uint64_t)(uintptr_t)testarea;
    range_struct.len = (uint64_t)pagesize;
    if (ioctl(ufd, UFFDIO_UNREGISTER, &range_struct)) {
        perror("postcopy_ram_supported_by_host userfault unregister");
        goto out;
    }

    feature_mask = (__u64)1 << _UFFDIO_WAKE |
                   (__u64)1 << _UFFDIO_COPY |
                   (__u64)1 << _UFFDIO_ZEROPAGE;
    if ((reg_struct.ioctls & feature_mask) != feature_mask) {
        error_report("Missing userfault map features: %" PRIu64,
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

#else
/* No target OS support, stubs just fail */

bool postcopy_ram_supported_by_host(void)
{
    error_report("%s: No OS support", __func__);
    return false;
}

/* Called by ram_load prior to mapping the page */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index)
{
    /* We don't support postcopy so don't care */
}

#endif

