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

//#define DEBUG_POSTCOPY

#ifdef DEBUG_POSTCOPY
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "postcopy@%" PRId64 " " fmt "\n", \
                          qemu_clock_get_ms(QEMU_CLOCK_REALTIME), \
                          ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

/* Postcopy needs to detect accesses to pages that haven't yet been copied
 * across, and efficiently map new pages in, the techniques for doing this
 * are target OS specific.
 */
#if defined(__linux__)

/* On Linux we use:
 *    madvise MADV_USERFAULT - to mark an area of anonymous memory such
 *                             that userspace is notifed of accesses to
 *                             unallocated areas.
 *    userfaultfd      - opens a socket to receive USERFAULT messages
 *    remap_anon_pages - to shuffle mapped pages into previously unallocated
 *                       areas without creating loads of VMAs.
 */

#include <sys/mman.h>
#include <sys/types.h>

/* TODO remove once we have libc defs */

#ifdef HOST_X86_64
 /* NOTE: These are Andrea's 3.15.0 world */
#ifndef MADV_USERFAULT
#define MADV_USERFAULT   18
#define MADV_NOUSERFAULT 19
#endif

#ifndef __NR_remap_anon_pages
#define __NR_remap_anon_pages 321
#endif

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 322
#endif

#endif

#ifndef USERFAULTFD_PROTOCOL
#define USERFAULTFD_PROTOCOL (uint64_t)0xaa
#endif

#endif

#if defined(__linux__) && defined(MADV_USERFAULT) && \
                          defined(__NR_remap_anon_pages)

/* ---------------------------------------------------------------------- */
/* Postcopy pagemap-inbound (pmi) - data structures that record the       */
/* state of each page used by the inbound postcopy                        */
/* It's a pair of bitmaps (of the same structure as the migration bitmaps)*/
/* holding one bit per target-page, although all operations work on host  */
/* pages.                                                                 */
__attribute__ (( unused )) /* Until later in patch series */
static void postcopy_pmi_init(MigrationIncomingState *mis, size_t ram_pages)
{
    unsigned int tpb = qemu_target_page_bits();
    unsigned long host_bits;

    qemu_mutex_init(&mis->postcopy_pmi.mutex);
    mis->postcopy_pmi.received_map = bitmap_new(ram_pages);
    mis->postcopy_pmi.requested_map = bitmap_new(ram_pages);
    bitmap_clear(mis->postcopy_pmi.received_map, 0, ram_pages);
    bitmap_clear(mis->postcopy_pmi.requested_map, 0, ram_pages);
    /*
     * Each bit in the map represents one 'target page' which is no bigger
     * than a host page but can be smaller.  It's useful to have some
     * convenience masks for later
     */

    /*
     * The number of bits one host page takes up in the bitmap
     * e.g. on a 64k host page, 4k Target page, host_bits=64/4=16
     */
    host_bits = sysconf(_SC_PAGESIZE) / (1ul << tpb);
    /* Should be a power of 2 */
    assert(host_bits && !(host_bits & (host_bits - 1)));
    /*
     * If the host_bits isn't a division of the number of bits in long
     * then the code gets a lot more complex; disallow for now
     * (I'm not aware of a system where it's true anyway)
     */
    assert(((sizeof(long) * 8) % host_bits) == 0);

    mis->postcopy_pmi.host_bits = host_bits;
    /* A mask, starting at bit 0, containing host_bits continuous set bits */
    mis->postcopy_pmi.host_mask =  (1ul << host_bits) - 1;

    assert((ram_pages % host_bits) == 0);
}

void postcopy_pmi_destroy(MigrationIncomingState *mis)
{
    if (mis->postcopy_pmi.received_map) {
        g_free(mis->postcopy_pmi.received_map);
        mis->postcopy_pmi.received_map = NULL;
    }
    if (mis->postcopy_pmi.requested_map) {
        g_free(mis->postcopy_pmi.requested_map);
        mis->postcopy_pmi.requested_map = NULL;
    }
    qemu_mutex_destroy(&mis->postcopy_pmi.mutex);
}

/*
 * Mark a set of pages in the PMI as being clear; this is used by the discard
 * at the start of postcopy, and before the postcopy stream starts.
 */
void postcopy_pmi_discard_range(MigrationIncomingState *mis,
                                size_t start, size_t npages)
{
    bitmap_clear(mis->postcopy_pmi.received_map, start, npages);
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
 */
static void set_hpbits(MigrationIncomingState *mis,
                       size_t bitmap_index, unsigned long *map)
{
    assert((bitmap_index & (mis->postcopy_pmi.host_bits-1)) == 0);

    map[BIT_WORD(bitmap_index)] |= mis->postcopy_pmi.host_mask <<
                                    (bitmap_index % BITS_PER_LONG);
}

/*
 * Clear host-page worth of bits in the map starting at bitmap_index
 */
static void clear_hpbits(MigrationIncomingState *mis,
                         size_t bitmap_index, unsigned long *map)
{
    assert((bitmap_index & (mis->postcopy_pmi.host_bits-1)) == 0);

    map[BIT_WORD(bitmap_index)] &= ~(mis->postcopy_pmi.host_mask <<
                                    (bitmap_index % BITS_PER_LONG));
}

/*
 * Retrieve the state of the given page
 * Note: This version for use by callers already holding the lock
 */
static PostcopyPMIState postcopy_pmi_get_state_nolock(
                            MigrationIncomingState *mis,
                            size_t bitmap_index)
{
    bool received, requested;

    received = test_hpbits(mis, bitmap_index, mis->postcopy_pmi.received_map);
    requested = test_hpbits(mis, bitmap_index, mis->postcopy_pmi.requested_map);

    if (received) {
        assert(!requested);
        return POSTCOPY_PMI_RECEIVED;
    } else {
        return requested ? POSTCOPY_PMI_REQUESTED : POSTCOPY_PMI_MISSING;
    }
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
          assert(0); /* This shouldn't actually happen - use discard_range */
          break;

        case POSTCOPY_PMI_REQUESTED:
          assert(old_state == POSTCOPY_PMI_MISSING);
          set_hpbits(mis, bitmap_index, mis->postcopy_pmi.requested_map);
          break;

        case POSTCOPY_PMI_RECEIVED:
          assert(old_state == POSTCOPY_PMI_MISSING ||
                 old_state == POSTCOPY_PMI_REQUESTED);
          set_hpbits(mis, bitmap_index, mis->postcopy_pmi.received_map);
          clear_hpbits(mis, bitmap_index, mis->postcopy_pmi.requested_map);
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
    fprintf(stderr, "postcopy_pmi_dump: requested\n");
    ram_debug_dump_bitmap(mis->postcopy_pmi.requested_map, false);
    fprintf(stderr, "postcopy_pmi_dump: received\n");
    ram_debug_dump_bitmap(mis->postcopy_pmi.received_map, true);
    fprintf(stderr, "postcopy_pmi_dump: end\n");
}

/* Called by ram_load prior to mapping the page */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index)
{
    if (mis->postcopy_ram_state == POSTCOPY_RAM_INCOMING_ADVISE) {
        /*
         * If we're in precopy-advise mode we need to track received pages even
         * though we don't need to place pages atomically yet.
         * In advise mode there's only a single thread, so don't need locks
         */
        set_bit(bitmap_index, mis->postcopy_pmi.received_map);
    }
}

int postcopy_ram_hosttest(void)
{
    /* TODO: Needs guarding with CONFIG_ once we have libc's that have the defs
     *
     * Try each syscall we need, but this isn't a testbench,
     * just enough to see that we have the calls
     */
    void *testarea = NULL, *testarea2 = NULL;
    long pagesize = getpagesize();
    int ufd = -1;
    int ret = -1; /* Error unless we change it */

    testarea = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE |
                                    MAP_ANONYMOUS, -1, 0);
    if (!testarea) {
        perror("postcopy_ram_hosttest: Failed to map test area");
        goto out;
    }
    g_assert(((size_t)testarea & (pagesize-1)) == 0);

    ufd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (ufd == -1) {
        perror("postcopy_ram_hosttest: userfaultfd not available");
        goto out;
    }

    if (madvise(testarea, pagesize, MADV_USERFAULT)) {
        perror("postcopy_ram_hosttest: MADV_USERFAULT not available");
        goto out;
    }

    if (madvise(testarea, pagesize, MADV_NOUSERFAULT)) {
        perror("postcopy_ram_hosttest: MADV_NOUSERFAULT not available");
        goto out;
    }

    testarea2 = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE |
                                     MAP_ANONYMOUS, -1, 0);
    if (!testarea2) {
        perror("postcopy_ram_hosttest: Failed to map second test area");
        goto out;
    }
    g_assert(((size_t)testarea2 & (pagesize-1)) == 0);
    *(char *)testarea = 0; /* Force the map of the new page */
    if (syscall(__NR_remap_anon_pages, testarea2, testarea, pagesize, 0) !=
        pagesize) {
        perror("postcopy_ram_hosttest: remap_anon_pages not available");
        goto out;
    }

    /* Success! */
    ret = 0;
out:
    if (testarea) {
        munmap(testarea, pagesize);
    }
    if (testarea2) {
        munmap(testarea2, pagesize);
    }
    if (ufd != -1) {
        close(ufd);
    }
    return ret;
}

#else
/* No target OS support, stubs just fail */

int postcopy_ram_hosttest(void)
{
    error_report("postcopy_ram_hosttest: No OS support");
    return -1;
}

/* Called by ram_load prior to mapping the page */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index)
{
    /* We don't support postcopy so don't care */
}

#endif

