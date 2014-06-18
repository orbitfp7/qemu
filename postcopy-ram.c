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

#endif

