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

#define MAX_DISCARDS_PER_COMMAND 12

struct PostcopyDiscardState {
    const char *name;
    uint16_t cur_entry;
    uint64_t addrlist[MAX_DISCARDS_PER_COMMAND];
    uint32_t masklist[MAX_DISCARDS_PER_COMMAND];
    uint8_t  offset;  /* Offset within 32bit mask at addr0 representing 1st
                         page of block */
    unsigned int nsentwords;
    unsigned int nsentcmds;
};

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

#include <poll.h>
#include <sys/eventfd.h>
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

/*
 * Setup an area of RAM so that it *can* be used for postcopy later; this
 * must be done right at the start prior to pre-copy.
 * opaque should be the MIS.
 */
static int init_area(const char *block_name, void *host_addr,
                     ram_addr_t offset, ram_addr_t length, void *opaque)
{
    MigrationIncomingState *mis = opaque;

    DPRINTF("init_area: %s: %p offset=%zx length=%zd(%zx)",
            block_name, host_addr, offset, length, length);
    /*
     * We need the whole of RAM to be truly empty for postcopy, so things
     * like ROMs and any data tables built during init must be zero'd
     * - we're going to get the copy from the source anyway.
     */
    if (postcopy_ram_discard_range(mis, host_addr, (host_addr + length - 1))) {
        return -1;
    }

    /*
     * We also need the area to be normal 4k pages, not huge pages
     * (otherwise we can't be sure we can use remap_anon_pages to put
     * a 4k page in later).  THP might come along and map a 2MB page
     * and when it's partially accessed in precopy it might not break
     * it down, but leave a 2MB zero'd page.
     */
    if (madvise(host_addr, length, MADV_NOHUGEPAGE)) {
        perror("init_area: NOHUGEPAGE");
        return -1;
    }

    return 0;
}

/*
 * At the end of migration, undo the effects of init_area
 * opaque should be the MIS.
 */
static int cleanup_area(const char *block_name, void *host_addr,
                        ram_addr_t offset, ram_addr_t length, void *opaque)
{
    /* Turn off userfault here as well? */

    DPRINTF("cleanup_area: %s: %p offset=%zx length=%zd(%zx)",
            block_name, host_addr, offset, length, length);
    /*
     * We turned off hugepage for the precopy stage with postcopy enabled
     * we can turn it back on now.
     */
    if (madvise(host_addr, length, MADV_HUGEPAGE)) {
        perror("init_area: HUGEPAGE");
        return -1;
    }

    /*
     * We can also turn off userfault now since we should have all the
     * pages.   It can be useful to leave it on to debug postcopy
     * if you're not sure it's always getting every page.
     */
    if (madvise(host_addr, length, MADV_NOUSERFAULT)) {
        perror("init_area: NOUSERFAULT");
        return -1;
    }

    return 0;
}

/*
 * Initialise postcopy-ram, setting the RAM to a state where we can go into
 * postcopy later; must be called prior to any precopy.
 * called from arch_init's similarly named ram_postcopy_incoming_init
 */
int postcopy_ram_incoming_init(MigrationIncomingState *mis, size_t ram_pages)
{
    postcopy_pmi_init(mis, ram_pages);
    mis->postcopy_place_skipped = -1;

    if (qemu_ram_foreach_block(init_area, mis)) {
        return -1;
    }

    return 0;
}

/*
 * At the end of a migration where postcopy_ram_incoming_init was called.
 */
int postcopy_ram_incoming_cleanup(MigrationIncomingState *mis)
{
    DPRINTF("%s: entry", __func__);
    if (qemu_ram_foreach_block(cleanup_area, mis)) {
        return -1;
    }

    if (mis->have_fault_thread) {
        uint64_t tmp64;
        /*
         * Tell the fault_thread to exit, it's an eventfd that should
         * currently be at 0, we're going to inc it to 1
         */
        tmp64 = 1;
        if (write(mis->userfault_quit_fd, &tmp64, 8) == 8) {
            DPRINTF("%s: Joining fault thread", __func__);
            qemu_thread_join(&mis->fault_thread);
        } else {
            /* Not much we can do here, but may as well report it */
            perror("incing userfault_quit_fd");
        }

        DPRINTF("%s: closing uf", __func__);
        close(mis->userfault_fd);
        close(mis->userfault_quit_fd);
        mis->have_fault_thread = false;
    }

    mis->postcopy_ram_state = POSTCOPY_RAM_INCOMING_END;
    migrate_send_rp_shut(mis, qemu_file_get_error(mis->file) != 0);

    if (mis->postcopy_tmp_page) {
        munmap(mis->postcopy_tmp_page, getpagesize());
        mis->postcopy_tmp_page = NULL;
    }
    DPRINTF("%s: exit", __func__);
    return 0;
}

/*
 * Mark the given area of RAM as requiring notification to unwritten areas
 * Used as a  callback on qemu_ram_foreach_block.
 *   host_addr: Base of area to mark
 *   offset: Offset in the whole ram arena
 *   length: Length of the section
 *   opaque: Unused
 * Returns 0 on success
 */
static int postcopy_ram_sensitise_area(const char *block_name, void *host_addr,
                                       ram_addr_t offset, ram_addr_t length,
                                       void *opaque)
{
    MigrationIncomingState *mis = opaque;
    uint64_t tokern[2];

    if (madvise(host_addr, length, MADV_USERFAULT)) {
        perror("postcopy_ram_sensitise_area madvise");
        return -1;
    }

    /* Now tell our userfault_fd that it's responsible for this area */
    tokern[0] = (uint64_t)(uintptr_t)host_addr | 1; /* 1 means register area */
    tokern[1] = (uint64_t)(uintptr_t)host_addr + length;
    if (write(mis->userfault_fd, tokern, 16) != 16) {
        perror("postcopy_ram_sensitise_area write");
        madvise(host_addr, length, MADV_NOUSERFAULT);
        return -1;
    }

    return 0;
}

/*
 * Tell the kernel that we've now got some memory it previously asked for.
 * Note: We're not allowed to ack a page which wasn't requested.
 */
static int ack_userfault(MigrationIncomingState *mis, void *start, size_t len)
{
    uint64_t tmp[2];

    /*
     * Kernel wants the range that's now safe to access
     * Note it always takes 64bit values, even on a 32bit host.
     */
    tmp[0] = (uint64_t)(uintptr_t)start;
    tmp[1] = (uint64_t)(uintptr_t)start + (uint64_t)len;

    if (write(mis->userfault_fd, tmp, 16) != 16) {
        int e = errno;

        if (e == ENOENT) {
            /* Kernel said it wasn't waiting - one case where this can
             * happen is where two threads triggered the userfault
             * and we receive the page and ack it just after we received
             * the 2nd request and that ends up deciding it should ack it
             * We could optimise it out, but it's rare.
             */
            /*fprintf(stderr, "ack_userfault: %p/%zx ENOENT\n", start, len); */
            return 0;
        }
        error_report("postcopy_ram: Failed to notify kernel for %p/%zx (%d)",
                     start, len, e);
        return -errno;
    }

    return 0;
}

/*
 * Handle faults detected by the USERFAULT markings
 */
static void *postcopy_ram_fault_thread(void *opaque)
{
    MigrationIncomingState *mis = (MigrationIncomingState *)opaque;
    void *hostaddr;
    int ret;
    size_t hostpagesize = getpagesize();
    RAMBlock *rb = NULL;
    RAMBlock *last_rb = NULL; /* last RAMBlock we sent part of */

    DPRINTF("%s", __func__);
    qemu_sem_post(&mis->fault_thread_sem);
    while (true) {
        PostcopyPMIState old_state, tmp_state;
        ram_addr_t rb_offset;
        ram_addr_t in_raspace;
        unsigned long bitmap_index;
        struct pollfd pfd[2];

        /*
         * We're mainly waiting for the kernel to give us a faulting HVA,
         * however we can be told to quit via userfault_quit_fd which is
         * an eventfd
         */
        pfd[0].fd = mis->userfault_fd;
        pfd[0].events = POLLIN;
        pfd[0].revents = 0;
        pfd[1].fd = mis->userfault_quit_fd;
        pfd[1].events = POLLIN; /* Waiting for eventfd to go positive */
        pfd[1].revents = 0;

        if (poll(pfd, 2, -1 /* Wait forever */) == -1) {
            perror("userfault poll");
            break;
        }

        if (pfd[1].revents) {
            DPRINTF("%s got quit event", __func__);
            break;
        }

        ret = read(mis->userfault_fd, &hostaddr, sizeof(hostaddr));
        if (ret != sizeof(hostaddr)) {
            if (ret < 0) {
                perror("Failed to read full userfault hostaddr");
                break;
            } else {
                error_report("%s: Read %d bytes from userfaultfd expected %zd",
                             __func__, ret, sizeof(hostaddr));
                break; /* Lost alignment, don't know what we'd read next */
            }
        }

        rb = qemu_ram_block_from_host(hostaddr, true, &in_raspace, &rb_offset,
                                      &bitmap_index);
        if (!rb) {
            error_report("postcopy_ram_fault_thread: Fault outside guest: %p",
                         hostaddr);
            break;
        }

        DPRINTF("%s: Request for HVA=%p index=%lx rb=%s offset=%zx",
                __func__, hostaddr, bitmap_index, qemu_ram_get_idstr(rb),
                rb_offset);

        tmp_state = postcopy_pmi_get_state(mis, bitmap_index);
        do {
            old_state = tmp_state;

            switch (old_state) {
            case POSTCOPY_PMI_REQUESTED:
                /* Do nothing - it's already requested */
                break;

            case POSTCOPY_PMI_RECEIVED:
                /* Already arrived - no state change, just kick the kernel */
                DPRINTF("postcopy_ram_fault_thread: notify pre of %p",
                        hostaddr);
                if (ack_userfault(mis,
                                  (void *)((uintptr_t)hostaddr
                                           & ~(hostpagesize - 1)),
                                  hostpagesize)) {
                    assert(0);
                }
                break;

            case POSTCOPY_PMI_MISSING:

                tmp_state = postcopy_pmi_change_state(mis, bitmap_index,
                                           old_state, POSTCOPY_PMI_REQUESTED);
                if (tmp_state == POSTCOPY_PMI_MISSING) {
                    /*
                     * Send the request to the source - we want to request one
                     * of our host page sizes (which is >= TPS)
                     */
                    if (rb != last_rb) {
                        last_rb = rb;
                        migrate_send_rp_reqpages(mis, qemu_ram_get_idstr(rb),
                                                 rb_offset, hostpagesize);
                    } else {
                        /* Save some space */
                        migrate_send_rp_reqpages(mis, NULL,
                                                 rb_offset, hostpagesize);
                    }
                }
                break;
           }
        } while (tmp_state != old_state);
    }
    DPRINTF("%s: exit", __func__);
    return NULL;
}

int postcopy_ram_enable_notify(MigrationIncomingState *mis)
{
    uint64_t tmp64;

    /* Open the fd for the kernel to give us userfaults */
    mis->userfault_fd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (mis->userfault_fd == -1) {
        perror("Failed to open userfault fd");
        return -1;
    }

    /*
     * Version handshake, we send it the version we want and expect to get the
     * same back.
     */
    tmp64 = USERFAULTFD_PROTOCOL;
    if (write(mis->userfault_fd, &tmp64, sizeof(tmp64)) != sizeof(tmp64)) {
        perror("Writing userfaultfd version");
        close(mis->userfault_fd);
        return -1;
    }
    if (read(mis->userfault_fd, &tmp64, sizeof(tmp64)) != sizeof(tmp64)) {
        perror("Reading userfaultfd version");
        close(mis->userfault_fd);
        return -1;
    }
    if (tmp64 != USERFAULTFD_PROTOCOL) {
        error_report("Mismatched userfaultfd version, expected %zx, got %zx",
                     (size_t)USERFAULTFD_PROTOCOL, (size_t)tmp64);
        close(mis->userfault_fd);
        return -1;
    }

    /* Now an eventfd we use to tell the fault-thread to quit */
    mis->userfault_quit_fd = eventfd(0, EFD_CLOEXEC);
    if (mis->userfault_quit_fd == -1) {
        perror("Opening userfault_quit_fd");
        close(mis->userfault_fd);
        return -1;
    }

    qemu_sem_init(&mis->fault_thread_sem, 0);
    qemu_thread_create(&mis->fault_thread, "postcopy/fault",
                       postcopy_ram_fault_thread, mis, QEMU_THREAD_JOINABLE);
    qemu_sem_wait(&mis->fault_thread_sem);
    mis->have_fault_thread = true;

    /* Mark so that we get notified of accesses to unwritten areas */
    if (qemu_ram_foreach_block(postcopy_ram_sensitise_area, mis)) {
        return -1;
    }

    DPRINTF("postcopy_ram_enable_notify: Sensitised");

    return 0;
}

/*
 * Place a zero'd page of memory at *host
 * returns 0 on success
 * bitmap_offset: Index into the migration bitmaps
 */
int postcopy_place_zero_page(MigrationIncomingState *mis, void *host,
                             long bitmap_offset)
{
    void *tmp = postcopy_get_tmp_page(mis, bitmap_offset);
    if (!tmp) {
        return -ENOMEM;
    }
    *(char *)tmp = 0;
    return postcopy_place_page(mis, host, tmp, bitmap_offset);
}

/*
 * Place a target page (from) at (host) efficiently
 *    There are restrictions on how 'from' must be mapped, in general best
 *    to use other postcopy_ routines to allocate.
 * returns 0 on success
 * bitmap_offset: Index into the migration bitmaps
 *
 * Where HPS > TPS it holds off doing the place until the last TP in the HP
 *  and assumes (from, host) point to the last TP in a continuous HP
 */
int postcopy_place_page(MigrationIncomingState *mis, void *host, void *from,
                        long bitmap_offset)
{
    PostcopyPMIState old_state, tmp_state;
    size_t hps = sysconf(_SC_PAGESIZE);

    /* Only place the page when the last target page within the hp arrives */
    if ((bitmap_offset + 1) & (mis->postcopy_pmi.host_bits - 1)) {
        DPRINTF("%s: Skipping incomplete hp host=%p from=%p bitmap_offset=%lx",
                __func__, host, from, bitmap_offset);
        mis->postcopy_place_skipped = bitmap_offset;
        return 0;
    }

    /*
     * If we skip a page (above) we should end up placing that page before
     * doing anything with other host pages.
     */
    if (mis->postcopy_place_skipped != -1) {
        assert((bitmap_offset & ~(mis->postcopy_pmi.host_bits - 1)) ==
               (mis->postcopy_place_skipped &
                ~(mis->postcopy_pmi.host_bits - 1)));
    }
    mis->postcopy_place_skipped = -1;

    /* Adjust pointers to point to start of host page */
    host = (void *)((uintptr_t)host & ~(hps - 1));
    from = (void *)((uintptr_t)from & ~(hps - 1));
    bitmap_offset -= (mis->postcopy_pmi.host_bits - 1);

    if (syscall(__NR_remap_anon_pages, host, from, hps, 0) !=
            getpagesize()) {
        int e = errno;
        perror("remap_anon_pages in postcopy_place_page");
        fprintf(stderr, "host: %p from: %p pmi=%d\n", host, from,
                postcopy_pmi_get_state(mis, bitmap_offset));

        return -e;
    }

    tmp_state = postcopy_pmi_get_state(mis, bitmap_offset);
    do {
        old_state = tmp_state;
        tmp_state = postcopy_pmi_change_state(mis, bitmap_offset, old_state,
                                              POSTCOPY_PMI_RECEIVED);

    } while (old_state != tmp_state);


    if (old_state == POSTCOPY_PMI_REQUESTED) {
        /* Send the kernel the host address that should now be accessible */
        DPRINTF("%s: Notifying kernel bitmap_offset=0x%lx host=%p",
                __func__, bitmap_offset, host);
        return ack_userfault(mis, host, hps);
    }

    return 0;
}

/*
 * Returns a target page of memory that can be mapped at a later point in time
 * using postcopy_place_page
 * The same address is used repeatedly, postcopy_place_page just takes the
 * backing page away.
 * Returns: Pointer to allocated page
 *
 * Note this is a target page and uses the bitmap_offset to get an offset
 * into a hostpage; since there's only one real temporary host page the caller
 * is expected to not flip around between pages.
 */
void *postcopy_get_tmp_page(MigrationIncomingState *mis, long bitmap_offset)
{
    ptrdiff_t offset;

    if (!mis->postcopy_tmp_page) {
        mis->postcopy_tmp_page = mmap(NULL, getpagesize(),
                             PROT_READ | PROT_WRITE, MAP_PRIVATE |
                             MAP_ANONYMOUS, -1, 0);
        if (!mis->postcopy_tmp_page) {
            perror("mapping postcopy tmp page");
            return NULL;
        }
        if (madvise(mis->postcopy_tmp_page, getpagesize(), MADV_DONTFORK)) {
            munmap(mis->postcopy_tmp_page, getpagesize());
            perror("postcpy tmp page DONTFORK");
            return NULL;
        }
    }

    /*
     * Get the offset within the host page based on bitmap_offset.
     */
    offset = (bitmap_offset & (mis->postcopy_pmi.host_bits - 1)) <<
                 qemu_target_page_bits();

    return (void *)((uint8_t *)mis->postcopy_tmp_page + offset);
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

int postcopy_ram_incoming_init(MigrationIncomingState *mis, size_t ram_pages)
{
    error_report("postcopy_ram_incoming_init: No OS support");
    return -1;
}

int postcopy_ram_incoming_cleanup(MigrationIncomingState *mis)
{
    assert(0);
}

void postcopy_pmi_destroy(MigrationIncomingState *mis)
{
    /* Called in normal cleanup path - so it's OK */
}

void postcopy_pmi_discard_range(MigrationIncomingState *mis,
                                size_t start, size_t npages)
{
    assert(0);
}

int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end)
{
    assert(0);
}

int postcopy_ram_enable_notify(MigrationIncomingState *mis)
{
    assert(0);
}

int postcopy_place_zero_page(MigrationIncomingState *mis, void *host,
                             long bitmap_offset)
{
    assert(0);
}

int postcopy_place_page(MigrationIncomingState *mis, void *host, void *from,
                        long bitmap_offset)
{
    assert(0);
}

void *postcopy_get_tmp_page(MigrationIncomingState *mis, long bitmap_offset)
{
    assert(0);
}

#endif

/* ------------------------------------------------------------------------- */

/*
 * Called at the start of each RAMBlock by the bitmap code
 * offset is the bit within the first 64bit chunk of mask
 * that represents the first page of the RAM Block
 * Returns a new PDS
 */
PostcopyDiscardState *postcopy_discard_send_init(MigrationState *ms,
                                                 uint8_t offset,
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
 */
void postcopy_discard_send_chunk(MigrationState *ms, PostcopyDiscardState *pds,
                                unsigned long pos, uint32_t bitmap)
{
    pds->addrlist[pds->cur_entry] = pos;
    pds->masklist[pds->cur_entry] = bitmap;
    pds->cur_entry++;
    pds->nsentwords++;

    if (pds->cur_entry == MAX_DISCARDS_PER_COMMAND) {
        /* Full set, ship it! */
        qemu_savevm_send_postcopy_ram_discard(ms->file, pds->name,
                                              pds->cur_entry, pds->offset,
                                              pds->addrlist, pds->masklist);
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
                                              pds->cur_entry, pds->offset,
                                              pds->addrlist, pds->masklist);
        pds->nsentcmds++;
    }

    DPRINTF("%s: '%s' mask words sent=%d in %d commands",
            __func__, pds->name, pds->nsentwords, pds->nsentcmds);

    g_free(pds);
}
