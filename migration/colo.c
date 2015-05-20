/*
 * COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 * (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (c) 2015 HUAWEI TECHNOLOGIES CO., LTD.
 * Copyright (c) 2015 FUJITSU LIMITED
 * Copyright (c) 2015 Intel Corporation
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include <unistd.h>
#include "sysemu/sysemu.h"
#include "migration/colo.h"
#include "trace.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"

bool colo_supported(void)
{
    return true;
}

bool migration_in_colo_state(void)
{
    MigrationState *s = migrate_get_current();

    return (s->state == MIGRATION_STATUS_COLO);
}

bool migration_incoming_in_colo_state(void)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    return mis && (mis->state == MIGRATION_STATUS_COLO);
}

static int colo_put_cmd(QEMUFile *f, uint32_t cmd)
{
    int ret;

    if (cmd >= COLO_COMMAND_MAX) {
        error_report("%s: Invalid cmd", __func__);
        return -EINVAL;
    }
    qemu_put_be32(f, cmd);
    qemu_fflush(f);

    ret = qemu_file_get_error(f);
    trace_colo_put_cmd(COLOCommand_lookup[cmd]);

    return ret;
}

static int colo_get_cmd(QEMUFile *f, uint32_t *cmd)
{
    int ret;

    *cmd = qemu_get_be32(f);
    ret = qemu_file_get_error(f);
    if (ret < 0) {
        return ret;
    }
    if (*cmd >= COLO_COMMAND_MAX) {
        error_report("%s: Invalid cmd", __func__);
        return -EINVAL;
    }
    trace_colo_get_cmd(COLOCommand_lookup[*cmd]);
    return 0;
}

static int colo_get_check_cmd(QEMUFile *f, uint32_t expect_cmd)
{
    int ret;
    uint32_t cmd;

    ret = colo_get_cmd(f, &cmd);
    if (ret < 0) {
        return ret;
    }
    if (cmd != expect_cmd) {
        error_report("Unexpect colo command, expect:%d, but got cmd:%d",
                     expect_cmd, cmd);
        return -EINVAL;
    }

    return 0;
}

static int colo_do_checkpoint_transaction(MigrationState *s)
{
    int ret;

    ret = colo_put_cmd(s->to_dst_file, COLO_COMMAND_CHECKPOINT_REQUEST);
    if (ret < 0) {
        goto out;
    }

    ret = colo_get_check_cmd(s->rp_state.from_dst_file,
                             COLO_COMMAND_CHECKPOINT_REPLY);
    if (ret < 0) {
        goto out;
    }

    /* TODO: suspend and save vm state to colo buffer */

    ret = colo_put_cmd(s->to_dst_file, COLO_COMMAND_VMSTATE_SEND);
    if (ret < 0) {
        goto out;
    }

    /* TODO: send vmstate to Secondary */

    ret = colo_get_check_cmd(s->rp_state.from_dst_file,
                             COLO_COMMAND_VMSTATE_RECEIVED);
    if (ret < 0) {
        goto out;
    }

    ret = colo_get_check_cmd(s->rp_state.from_dst_file,
                             COLO_COMMAND_VMSTATE_LOADED);
    if (ret < 0) {
        goto out;
    }

    /* TODO: resume Primary */

out:
    return ret;
}

static void colo_process_checkpoint(MigrationState *s)
{
    int ret = 0;

    s->rp_state.from_dst_file = qemu_file_get_return_path(s->to_dst_file);
    if (!s->rp_state.from_dst_file) {
        ret = -EINVAL;
        error_report("Open QEMUFile from_dst_file failed");
        goto out;
    }

    /*
     * Wait for Secondary finish loading vm states and enter COLO
     * restore.
     */
    ret = colo_get_check_cmd(s->rp_state.from_dst_file,
                             COLO_COMMAND_CHECKPOINT_READY);
    if (ret < 0) {
        goto out;
    }

    qemu_mutex_lock_iothread();
    vm_start();
    qemu_mutex_unlock_iothread();
    trace_colo_vm_state_change("stop", "run");

    while (s->state == MIGRATION_STATUS_COLO) {
        /* start a colo checkpoint */
        ret = colo_do_checkpoint_transaction(s);
        if (ret < 0) {
            goto out;
        }
    }

out:
    if (ret < 0) {
        error_report("%s: %s", __func__, strerror(-ret));
    }
    migrate_set_state(&s->state, MIGRATION_STATUS_COLO,
                      MIGRATION_STATUS_COMPLETED);

    if (s->rp_state.from_dst_file) {
        qemu_fclose(s->rp_state.from_dst_file);
    }
}

void migrate_start_colo_process(MigrationState *s)
{
    qemu_mutex_unlock_iothread();
    migrate_set_state(&s->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COLO);
    colo_process_checkpoint(s);
    qemu_mutex_lock_iothread();
}

/*
 * return:
 * 0: start a checkpoint
 * -1: some error happened, exit colo restore
 */
static int colo_wait_handle_cmd(QEMUFile *f, int *checkpoint_request)
{
    int ret;
    uint32_t cmd;

    ret = colo_get_cmd(f, &cmd);
    if (ret < 0) {
        /* do failover ? */
        return ret;
    }

    switch (cmd) {
    case COLO_COMMAND_CHECKPOINT_REQUEST:
        *checkpoint_request = 1;
        return 0;
    default:
        return -EINVAL;
    }
}

void *colo_process_incoming_thread(void *opaque)
{
    MigrationIncomingState *mis = opaque;
    int ret = 0;

    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COLO);

    mis->to_src_file = qemu_file_get_return_path(mis->from_src_file);
    if (!mis->to_src_file) {
        ret = -EINVAL;
        error_report("colo incoming thread: Open QEMUFile to_src_file failed");
        goto out;
    }
    /* Note: We set the fd to unblocked in migration incoming coroutine,
    *  But here we are in the colo incoming thread, so it is ok to set the
    *  fd back to blocked.
    */
    qemu_set_block(qemu_get_fd(mis->from_src_file));


    ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_CHECKPOINT_READY);
    if (ret < 0) {
        goto out;
    }

    while (mis->state == MIGRATION_STATUS_COLO) {
        int request = 0;
        int ret = colo_wait_handle_cmd(mis->from_src_file, &request);

        if (ret < 0) {
            break;
        } else {
            if (!request) {
                continue;
            }
        }
        /* FIXME: This is unnecessary for periodic checkpoint mode */
        ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_CHECKPOINT_REPLY);
        if (ret < 0) {
            goto out;
        }

        ret = colo_get_check_cmd(mis->from_src_file,
                                 COLO_COMMAND_VMSTATE_SEND);
        if (ret < 0) {
            goto out;
        }

        /* TODO: read migration data into colo buffer */

        ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_VMSTATE_RECEIVED);
        if (ret < 0) {
            goto out;
        }

        /* TODO: load vm state */

        ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_VMSTATE_LOADED);
        if (ret < 0) {
            goto out;
        }
    }

out:
    if (ret < 0) {
        error_report("colo incoming thread will exit, detect error: %s",
                     strerror(-ret));
    }

    if (mis->to_src_file) {
        qemu_fclose(mis->to_src_file);
    }
    migration_incoming_exit_colo();

    return NULL;
}
