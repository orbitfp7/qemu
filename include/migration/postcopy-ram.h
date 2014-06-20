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

/* Send the list of sent-but-dirty pages */
int postcopy_send_discard_bitmap(MigrationState *ms);

/*
 * Discard the contents of memory start..end inclusive.
 * We can assume that if we've been called postcopy_ram_hosttest returned true
 */
int postcopy_ram_discard_range(MigrationIncomingState *mis, uint8_t *start,
                               uint8_t *end);


/*
 * Called back from arch_init's ram_postcopy_each_ram_discard to handle
 * discarding one RAMBlock's pre-postcopy dirty pages
 */
int postcopy_send_discard_bm_ram(MigrationState *ms, const char *name,
                                 unsigned long start, unsigned long end);

/*
 * In 'advise' mode record that a page has been received.
 */
void postcopy_hook_early_receive(MigrationIncomingState *mis,
                                 size_t bitmap_index);

void postcopy_pmi_destroy(MigrationIncomingState *mis);
void postcopy_pmi_discard_range(MigrationIncomingState *mis,
                                size_t start, size_t npages);
void postcopy_pmi_dump(MigrationIncomingState *mis);
#endif
