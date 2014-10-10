/*
 * Postcopy migration for RAM
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Dave Gilbert  <dgilbert@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#ifndef QEMU_POSTCOPY_RAM_H
#define QEMU_POSTCOPY_RAM_H

#include "migration/migration.h"

/* Return 0 if the host supports everything we need to do postcopy-ram */
int postcopy_ram_hosttest(void);

/*
 * Make all of RAM sensitive to accesses to areas that haven't yet been written
 * and wire up anything necessary to deal with it.
 */
int postcopy_ram_enable_notify(MigrationIncomingState *mis);

/*
 * Initialise postcopy-ram, setting the RAM to a state where we can go into
 * postcopy later; must be called prior to any precopy.
 * called from arch_init's similarly named ram_postcopy_incoming_init
 */
int postcopy_ram_incoming_init(MigrationIncomingState *mis, size_t ram_pages);

/*
 * At the end of a migration where postcopy_ram_incoming_init was called.
 */
int postcopy_ram_incoming_cleanup(MigrationIncomingState *mis);

/*
 * In 'advise' mode record that a page has been received.
 */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index);

void postcopy_pmi_destroy(MigrationIncomingState *mis);
void postcopy_pmi_discard_range(MigrationIncomingState *mis,
                                size_t start, size_t npages);
void postcopy_pmi_dump(MigrationIncomingState *mis);

/*
 * Discard the contents of memory start..end inclusive.
 * We can assume that if we've been called postcopy_ram_hosttest returned true
 */
int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end);


/*
 * Called at the start of each RAMBlock by the bitmap code
 * offset is the bit within the first 32bit chunk of mask
 * that represents the first page of the RAM Block
 * Returns a new PDS
 */
PostcopyDiscardState *postcopy_discard_send_init(MigrationState *ms,
                                                 uint8_t offset,
                                                 const char *name);

/*
 * Called by the bitmap code for each chunk to discard
 * May send a discard message, may just leave it queued to
 * be sent later
 */
void postcopy_discard_send_chunk(MigrationState *ms, PostcopyDiscardState *pds,
                                unsigned long pos, uint32_t bitmap);

/*
 * Called at the end of each RAMBlock by the bitmap code
 * Sends any outstanding discard messages, frees the PDS
 */
void postcopy_discard_send_finish(MigrationState *ms,
                                  PostcopyDiscardState *pds);

/*
 * Place a zero'd page of memory at *host
 * returns 0 on success
 */
int postcopy_place_zero_page(MigrationIncomingState *mis, void *host,
                             long bitmap_offset);

/*
 * Place a page (from) at (host) efficiently
 *    There are restrictions on how 'from' must be mapped, in general best
 *    to use other postcopy_ routines to allocate.
 * returns 0 on success
 */
int postcopy_place_page(MigrationIncomingState *mis, void *host, void *from,
                        long bitmap_offset);

/*
 * Allocate a page of memory that can be mapped at a later point in time
 * using postcopy_place_page
 * Returns: Pointer to allocated page
 */
void *postcopy_get_tmp_page(MigrationIncomingState *mis, long bitmap_offset);

#endif
