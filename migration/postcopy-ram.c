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

#include <poll.h>
#include <sys/eventfd.h>
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
    if (postcopy_state_get(mis) == POSTCOPY_INCOMING_ADVISE) {
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


/*
 * Note: This has the side effect of munlock'ing all of RAM, that's
 * normally fine since if the postcopy succeeds it gets turned back on at the
 * end.
 */
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
     * userfault and mlock don't go together; we'll put it back later if
     * it was enabled.
     */
    if (munlockall()) {
        perror("postcopy_ram_incoming_init: munlockall");
        return -1;
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

    trace_postcopy_init_area(block_name, host_addr, offset, length);

    /*
     * We need the whole of RAM to be truly empty for postcopy, so things
     * like ROMs and any data tables built during init must be zero'd
     * - we're going to get the copy from the source anyway.
     * (Precopy will just overwrite this data, so doesn't need the discard)
     */
    if (postcopy_ram_discard_range(mis, host_addr, (host_addr + length - 1))) {
        return -1;
    }

    /*
     * We also need the area to be normal 4k pages, not huge pages
     * (otherwise we can't be sure we can atopically place the
     * 4k page in later).  THP might come along and map a 2MB page
     * and when it's partially accessed in precopy it might not break
     * it down, but leave a 2MB zero'd page.
     */
#ifdef MADV_NOHUGEPAGE
    if (madvise(host_addr, length, MADV_NOHUGEPAGE)) {
        perror("init_area: NOHUGEPAGE");
        return -1;
    }
#endif

    return 0;
}

/*
 * At the end of migration, undo the effects of init_area
 * opaque should be the MIS.
 */
static int cleanup_area(const char *block_name, void *host_addr,
                        ram_addr_t offset, ram_addr_t length, void *opaque)
{
    MigrationIncomingState *mis = opaque;
    struct uffdio_range range_struct;
    trace_postcopy_cleanup_area(block_name, host_addr, offset, length);

    /*
     * We turned off hugepage for the precopy stage with postcopy enabled
     * we can turn it back on now.
     */
#ifdef MADV_HUGEPAGE
    if (madvise(host_addr, length, MADV_HUGEPAGE)) {
        perror("cleanup_area: HUGEPAGE");
        return -1;
    }
#endif

    /*
     * We can also turn off userfault now since we should have all the
     * pages.   It can be useful to leave it on to debug postcopy
     * if you're not sure it's always getting every page.
     */
    range_struct.start = (uint64_t)(uintptr_t)host_addr;
    range_struct.len = (uint64_t)length;

    if (ioctl(mis->userfault_fd, UFFDIO_UNREGISTER, &range_struct)) {
        perror("cleanup_area: userfault unregister");

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
    trace_postcopy_ram_incoming_cleanup_entry();

    if (mis->have_fault_thread) {
        uint64_t tmp64;

        if (qemu_ram_foreach_block(cleanup_area, mis)) {
            return -1;
        }
        /*
         * Tell the fault_thread to exit, it's an eventfd that should
         * currently be at 0, we're going to inc it to 1
         */
        tmp64 = 1;
        if (write(mis->userfault_quit_fd, &tmp64, 8) == 8) {
            trace_postcopy_ram_incoming_cleanup_join();
            qemu_thread_join(&mis->fault_thread);
        } else {
            /* Not much we can do here, but may as well report it */
            perror("incing userfault_quit_fd");
        }
        trace_postcopy_ram_incoming_cleanup_closeuf();
        close(mis->userfault_fd);
        close(mis->userfault_quit_fd);
        mis->have_fault_thread = false;
    }

    if (enable_mlock) {
        if (os_mlock() < 0) {
            error_report("mlock: %s", strerror(errno));
            /*
             * It doesn't feel right to fail at this point, we have a valid
             * VM state.
             */
        }
    }

    postcopy_state_set(mis, POSTCOPY_INCOMING_END);
    migrate_send_rp_shut(mis, qemu_file_get_error(mis->file) != 0);

    if (mis->postcopy_tmp_page) {
        munmap(mis->postcopy_tmp_page, getpagesize());
        mis->postcopy_tmp_page = NULL;
    }
    trace_postcopy_ram_incoming_cleanup_exit();
    return 0;
}

/*
 * Mark the given area of RAM as requiring notification to unwritten areas
 * Used as a  callback on qemu_ram_foreach_block.
 *   host_addr: Base of area to mark
 *   offset: Offset in the whole ram arena
 *   length: Length of the section
 *   opaque: MigrationIncomingState pointer
 * Returns 0 on success
 */
static int ram_block_enable_notify(const char *block_name, void *host_addr,
                                   ram_addr_t offset, ram_addr_t length,
                                   void *opaque)
{
    MigrationIncomingState *mis = opaque;
    struct uffdio_register reg_struct;

    reg_struct.range.start = (uint64_t)(uintptr_t)host_addr;
    reg_struct.range.len = (uint64_t)length;
    reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;

    /* Now tell our userfault_fd that it's responsible for this area */
    if (ioctl(mis->userfault_fd, UFFDIO_REGISTER, &reg_struct)) {
        perror("ram_block_enable_notify userfault register");
        return -1;
    }

    return 0;
}

/*
 * Tell the kernel that we've now got some memory it previously asked for.
 */
static int ack_userfault(MigrationIncomingState *mis, void *start, size_t len)
{
    struct uffdio_range range_struct;

    range_struct.start = (uint64_t)(uintptr_t)start;
    range_struct.len = (uint64_t)len;

    errno = 0;
    if (ioctl(mis->userfault_fd, UFFDIO_WAKE, &range_struct)) {
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
        return -e;
    }

    return 0;
}

/*
 * Handle faults detected by the USERFAULT markings
 */
static void *postcopy_ram_fault_thread(void *opaque)
{
    MigrationIncomingState *mis = (MigrationIncomingState *)opaque;
    uint64_t hostaddr; /* The kernel always gives us 64 bit, not a pointer */
    int ret;
    size_t hostpagesize = getpagesize();
    RAMBlock *rb = NULL;
    RAMBlock *last_rb = NULL; /* last RAMBlock we sent part of */
    uint8_t *local_tmp_page;

    trace_postcopy_ram_fault_thread_entry();
    qemu_sem_post(&mis->fault_thread_sem);

    local_tmp_page = mmap(NULL, getpagesize(),
                          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    if (!local_tmp_page) {
        perror("mapping local tmp page");
        return NULL;
    }
    if (madvise(local_tmp_page, getpagesize(), MADV_DONTFORK)) {
        munmap(local_tmp_page, getpagesize());
        perror("postcpy local page DONTFORK");
        return NULL;
    }

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
            trace_postcopy_ram_fault_thread_quit();
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

        rb = qemu_ram_block_from_host((void *)(uintptr_t)hostaddr, true,
                                      &in_raspace, &rb_offset, &bitmap_index);
        if (!rb) {
            error_report("postcopy_ram_fault_thread: Fault outside guest: %"
                         PRIx64, hostaddr);
            break;
        }

        trace_postcopy_ram_fault_thread_request(hostaddr, bitmap_index,
                                                qemu_ram_get_idstr(rb),
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
                trace_postcopy_ram_fault_thread_notify_pre(hostaddr);
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
                        migrate_send_rp_req_pages(mis, qemu_ram_get_idstr(rb),
                                                 rb_offset, hostpagesize);
                    } else {
                        /* Save some space */
                        migrate_send_rp_req_pages(mis, NULL,
                                                 rb_offset, hostpagesize);
                    }
                } /* else it just arrived from the source and the kernel will
                     be kicked during the receive */
                break;
           }
        } while (tmp_state != old_state);
    }
    munmap(local_tmp_page, getpagesize());
    trace_postcopy_ram_fault_thread_exit();
    return NULL;
}

int postcopy_ram_enable_notify(MigrationIncomingState *mis)
{
    /* Open the fd for the kernel to give us userfaults */
    mis->userfault_fd = syscall(__NR_userfaultfd, O_CLOEXEC);
    if (mis->userfault_fd == -1) {
        perror("Failed to open userfault fd");
        return -1;
    }

    /*
     * Although the host check already tested the API, we need to
     * do the check again as an ABI handshake on the new fd.
     */
    if (!ufd_version_check(mis->userfault_fd)) {
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
    qemu_sem_destroy(&mis->fault_thread_sem);
    mis->have_fault_thread = true;

    /* Mark so that we get notified of accesses to unwritten areas */
    if (qemu_ram_foreach_block(ram_block_enable_notify, mis)) {
        return -1;
    }

    trace_postcopy_ram_enable_notify();

    return 0;
}

/*
 * Place a host page (from) at (host) tomically
 *    There are restrictions on how 'from' must be mapped, in general best
 *    to use other postcopy_ routines to allocate.
 * all_zero: Hint that the page being placed is 0 throughout
 * returns 0 on success
 * bitmap_offset: Index into the migration bitmaps
 *
 * State changes:
 *   none -> received
 *   requested -> received (ack)
 *
 * Note the UF thread is also updating the state, and maybe none->requested
 * at the same time.
 */
int postcopy_place_page(MigrationIncomingState *mis, void *host, void *from,
                        long bitmap_offset, bool all_zero)
{
    PostcopyPMIState old_state, tmp_state, new_state;

    if (!all_zero) {
        struct uffdio_copy copy_struct;

        copy_struct.dst = (uint64_t)(uintptr_t)host;
        copy_struct.src = (uint64_t)(uintptr_t)from;
        copy_struct.len = getpagesize();
        copy_struct.mode = 0;

        /* copy also acks to the kernel waking the stalled thread up
         * TODO: We can inhibit that ack and only do it if it was requested
         * which would be slightly cheaper, but we'd have to be careful
         * of the order of updating our page state.
         */
        if (ioctl(mis->userfault_fd, UFFDIO_COPY, &copy_struct)) {
            int e = errno;
            error_report("%s: %s copy host: %p from: %p pmi=%d",
                         __func__, strerror(e), host, from,
                         postcopy_pmi_get_state(mis, bitmap_offset));

            return -e;
        }
    } else {
        struct uffdio_zeropage zero_struct;

        zero_struct.range.start = (uint64_t)(uintptr_t)host;
        zero_struct.range.len = getpagesize();
        zero_struct.mode = 0;

        if (ioctl(mis->userfault_fd, UFFDIO_ZEROPAGE, &zero_struct)) {
            int e = errno;
            error_report("%s: %s zero host: %p from: %p pmi=%d",
                         __func__, strerror(e), host, from,
                         postcopy_pmi_get_state(mis, bitmap_offset));

            return -e;
        }
    }

    bitmap_offset &= ~(mis->postcopy_pmi.host_bits-1);
    new_state = POSTCOPY_PMI_RECEIVED;
    tmp_state = postcopy_pmi_get_state(mis, bitmap_offset);
    do {
        old_state = tmp_state;
        tmp_state = postcopy_pmi_change_state(mis, bitmap_offset, old_state,
                                              new_state);
    } while (old_state != tmp_state);
    trace_postcopy_place_page(bitmap_offset, host, all_zero, old_state);

    return 0;
}

/*
 * Returns a target page of memory that can be mapped at a later point in time
 * using postcopy_place_page
 * The same address is used repeatedly, postcopy_place_page just takes the
 * backing page away.
 * Returns: Pointer to allocated page
 *
 */
void *postcopy_get_tmp_page(MigrationIncomingState *mis)
{
    if (!mis->postcopy_tmp_page) {
        mis->postcopy_tmp_page = mmap(NULL, getpagesize(),
                             PROT_READ | PROT_WRITE, MAP_PRIVATE |
                             MAP_ANONYMOUS, -1, 0);
        if (!mis->postcopy_tmp_page) {
            perror("mapping postcopy tmp page");
            return NULL;
        }
    }

    return mis->postcopy_tmp_page;
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

int postcopy_place_page(MigrationIncomingState *mis, void *host, void *from,
                        long bitmap_offset, bool all_zero)
{
    assert(0);
}

void *postcopy_get_tmp_page(MigrationIncomingState *mis)
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

    trace_postcopy_discard_send_finish(pds->name, pds->nsentwords,
                                       pds->nsentcmds);

    g_free(pds);
}
