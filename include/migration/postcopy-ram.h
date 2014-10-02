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

/* Return true if the host supports everything we need to do postcopy-ram */
bool postcopy_ram_supported_by_host(void);

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
