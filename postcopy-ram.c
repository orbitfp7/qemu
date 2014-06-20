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

/* TODO remove once we have libc defs
 * NOTE: These are x86-64 numbers for Andrea's 3.15.0 world */
#ifndef MADV_USERFAULT
#define MADV_USERFAULT   18
#define MADV_NOUSERFAULT 19
#endif

#ifndef __NR_remap_anon_pages
#define __NR_remap_anon_pages 317
#endif

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 318
#endif

#ifndef USERFAULTFD_PROTOCOL
#define USERFAULTFD_PROTOCOL (uint64_t)0xaa
#endif

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

/*
 * Discard the contents of memory start..end inclusive.
 * We can assume that if we've been called postcopy_ram_hosttest returned true
 */
int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end)
{
    if (madvise(start, (end-start)+1, MADV_DONTNEED)) {
        perror("postcopy_ram_discard_range MADV_DONTNEED");
        return -1;
    }

    return 0;
}

#else
/* No target OS support, stubs just fail */

int postcopy_ram_hosttest(void)
{
    error_report("postcopy_ram_hosttest: No OS support");
    return -1;
}

int postcopy_ram_discard_range(MigrationIncomingState *mis, void *start,
                               void *end)
{
    error_report("postcopy_ram_discard_range: No OS support");
    return -1;
}
#endif

/* ------------------------------------------------------------------------- */
/*
 * A helper to get 64 bits from the sentmap; trivial for HOST_LONG_BITS=64
 * messier for other sizes; pads with 0's at end if an unaligned end
 *   check2nd32: True if it's safe to read the upper 32bits in a 32bit long
 *               map
 */
static uint64_t get_64bits_sentmap(unsigned long *sentmap, bool check2nd32,
                                   int64_t start)
{
    uint64_t result;
#if HOST_LONG_BITS == 64
    result = sentmap[start / 64];
#elif HOST_LONG_BITS == 32
    /*
     * Irrespective of host endianness, sentmap[n] is for pages earlier
     * than sentmap[n+1] so we can't just cast up
     */
    uint32_t sm0, sm1;
    sm0 = sentmap[start / 32];
    sm1 = check2nd32 ? sentmap[(start / 32) + 1] : 0;
    result = sm0 | ((uint64_t)sm1) << 32;
#else
#error "Host long other than 64/32 not supported"
#endif

    return result;
}

/*
 * Callback from ram_postcopy_each_ram_discard for each RAMBlock
 * start,end: Indexes into the bitmap for the first and last bit
 *            representing the named block
 */
int postcopy_send_discard_bm_ram(MigrationState *ms, const char *name,
                                 unsigned long start, unsigned long end)
{
    /* Keeps command under 256 bytes - but arbitrary */
    const unsigned int max_entries_per_command = 12;
    uint16_t cur_entry;
    uint64_t buffer[2*max_entries_per_command];
    unsigned int nsentwords = 0;
    unsigned int nsentcmds = 0;

    /*
     * There is no guarantee that start, end are on convenient 64bit multiples
     * (We always send 64bit chunks over the wire, irrespective of long size)
     */
    unsigned long first64, last64, cur64;
    first64 = start / 64;
    last64 = end / 64;

    cur_entry = 0;
    for (cur64 = first64; cur64 <= last64; cur64++) {
        /* Deal with start/end not on alignment */
        uint64_t mask;
        mask = ~(uint64_t)0;

        if ((cur64 == first64) && (start & 63)) {
            /* e.g. (start & 63) = 3
             *         1 << .    -> 2^3
             *         . - 1     -> 2^3 - 1 i.e. mask 2..0
             *         ~.        -> mask 63..3
             */
            mask &= ~((((uint64_t)1) << (start & 63)) - 1);
        }

        if ((cur64 == last64) && ((end & 64) != 63)) {
            /* e.g. (end & 64) = 3
             *            .   +1 -> 4
             *         1 << .    -> 2^4
             *         . -1      -> 2^4 - 1
             *                   = mask set 3..0
             */
            mask &= (((uint64_t)1) << ((end & 64) + 1)) - 1;
        }

        uint64_t data = get_64bits_sentmap(ms->sentmap,
                                           (end & 64) >= 32, cur64 * 64);
        data &= mask;

        if (data) {
            cpu_to_be64w(buffer+2*cur_entry, (cur64-first64));
            cpu_to_be64w(buffer+1+2*cur_entry, data);
            cur_entry++;
            nsentwords++;

            if (cur_entry == max_entries_per_command) {
                /* Full set, ship it! */
                qemu_savevm_send_postcopy_ram_discard(ms->file, name,
                                                      cur_entry,
                                                      start & 63,
                                                      buffer);
                nsentcmds++;
                cur_entry = 0;
            }
        }
    }

    /* Anything unsent? */
    if (cur_entry) {
        qemu_savevm_send_postcopy_ram_discard(ms->file, name, cur_entry,
                                              start & 63, buffer);
        nsentcmds++;
    }

    /*fprintf(stderr, "postcopy_send_discard_bm_ram: '%s' mask words"
                      " sent=%d in %d commands.\n",
            name, nsentwords, nsentcmds);*/

    return 0;
}

/*
 * Transmit the set of pages to be discarded after precopy to the target
 * these are pages that have been sent previously but have been dirtied
 * Hopefully this is pretty sparse
 */
int postcopy_send_discard_bitmap(MigrationState *ms)
{
    /*
     * Update the sentmap to be  sentmap&=dirty
     * (arch_init gives us the full size as a return)
     */
    ram_mask_postcopy_bitmap(ms);

    DPRINTF("Dumping merged sentmap");
#ifdef DEBUG_POSTCOPY
    ram_debug_dump_bitmap(ms->sentmap, false);
#endif

    return ram_postcopy_each_ram_discard(ms);
}

