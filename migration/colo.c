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
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "migration/colo.h"
#include "trace.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "migration/failover.h"
#include "qapi-event.h"
#include "net/filter.h"
#include "net/net.h"
#include "block/block_int.h"

static bool vmstate_loading;

/* colo buffer */
#define COLO_BUFFER_BASE_SIZE (4 * 1024 * 1024)

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

static bool colo_runstate_is_stopped(void)
{
    return runstate_check(RUN_STATE_COLO) || !runstate_is_running();
}

static void secondary_vm_do_failover(void)
{
    int old_state;
    MigrationIncomingState *mis = migration_incoming_get_current();
    Error *local_err = NULL;

    /* Can not do failover during the process of VM's loading VMstate, Or
      * it will break the secondary VM.
      */
    if (vmstate_loading) {
        old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                       FAILOVER_STATUS_RELAUNCH);
        if (old_state != FAILOVER_STATUS_HANDLING) {
            error_report("Unknow error while do failover for secondary VM,"
                         "old_state: %d", old_state);
        }
        return;
    }

    migrate_set_state(&mis->state, MIGRATION_STATUS_COLO,
                      MIGRATION_STATUS_COMPLETED);

    bdrv_stop_replication_all(true, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    trace_colo_stop_block_replication("failover");

    if (!autostart) {
        error_report("\"-S\" qemu option will be ignored in secondary side");
        /* recover runstate to normal migration finish state */
        autostart = true;
    }
    /*
    * Make sure colo incoming thread not block in recv or send,
    * If mis->from_src_file and mis->to_src_file use the same fd,
    * The second shutdown() will return -1, we ignore this value,
    * it is harmless.
    */
    if (mis->from_src_file) {
        qemu_file_shutdown(mis->from_src_file);
    }
    if (mis->to_src_file) {
        qemu_file_shutdown(mis->to_src_file);
    }

    old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                   FAILOVER_STATUS_COMPLETED);
    if (old_state != FAILOVER_STATUS_HANDLING) {
        error_report("Incorrect state (%d) while doing failover for "
                     "secondary VM", old_state);
        return;
    }
    /* For Secondary VM, jump to incoming co */
    if (mis->migration_incoming_co) {
        qemu_coroutine_enter(mis->migration_incoming_co, NULL);
    }
}

static void primary_vm_do_failover(void)
{
    MigrationState *s = migrate_get_current();
    int old_state;
    Error *local_err = NULL;

    migrate_set_state(&s->state, MIGRATION_STATUS_COLO,
                      MIGRATION_STATUS_COMPLETED);

    /*
    * Make sure colo thread no block in recv or send,
    * The s->rp_state.from_dst_file and s->to_dst_file may use the
    * same fd, but we still shutdown the fd for twice, it is harmless.
    */
    if (s->to_dst_file) {
        qemu_file_shutdown(s->to_dst_file);
    }
    if (s->rp_state.from_dst_file) {
        qemu_file_shutdown(s->rp_state.from_dst_file);
    }

    old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                   FAILOVER_STATUS_COMPLETED);
    if (old_state != FAILOVER_STATUS_HANDLING) {
        error_report("Incorrect state (%d) while doing failover for Primary VM",
                     old_state);
        return;
    }
    /* Don't buffer any packets while exited COLO */
    qemu_set_default_filters_status(false);
    /* Flush the residuary buffered packts */
    qemu_release_default_filters_packets();

    bdrv_stop_replication_all(true, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    trace_colo_stop_block_replication("failover");
}

void colo_do_failover(MigrationState *s)
{
    /* Make sure vm stopped while failover */
    if (!colo_runstate_is_stopped()) {
        vm_stop_force_state(RUN_STATE_COLO);
    }

    if (get_colo_mode() == COLO_MODE_PRIMARY) {
        primary_vm_do_failover();
    } else {
        secondary_vm_do_failover();
    }
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

static int colo_put_cmd_value(QEMUFile *f, uint32_t cmd, uint64_t value)
{
    int ret;

    ret = colo_put_cmd(f, cmd);
    if (ret < 0) {
        return 0;
     }
    qemu_put_be64(f, value);
    qemu_fflush(f);

    ret = qemu_file_get_error(f);

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

static int colo_get_cmd_value(QEMUFile *f, uint32_t expect_cmd, uint64_t *value)
{
    int ret;

    ret = colo_get_check_cmd(f, expect_cmd);
    if (ret < 0) {
        return ret;
    }

    *value = qemu_get_be64(f);
    ret = qemu_file_get_error(f);

    return ret;
}

static int colo_do_checkpoint_transaction(MigrationState *s,
                                          QEMUSizedBuffer *buffer)
{
    int ret;
    int colo_shutdown;
    size_t size;
    QEMUFile *trans = NULL;
    Error *local_err = NULL;

    ret = colo_put_cmd(s->to_dst_file, COLO_COMMAND_CHECKPOINT_REQUEST);
    if (ret < 0) {
        goto out;
    }

    ret = colo_get_check_cmd(s->rp_state.from_dst_file,
                             COLO_COMMAND_CHECKPOINT_REPLY);
    if (ret < 0) {
        goto out;
    }
    /* Reset colo buffer and open it for write */
    qsb_set_length(buffer, 0);
    trans = qemu_bufopen("w", buffer);
    if (!trans) {
        error_report("Open colo buffer for write failed");
        goto out;
    }

    qemu_mutex_lock_iothread();
    if (failover_request_is_active()) {
        qemu_mutex_unlock_iothread();
        ret = -1;
        goto out;
    }
    colo_shutdown = colo_shutdown_requested;
    vm_stop_force_state(RUN_STATE_COLO);
    qemu_mutex_unlock_iothread();
    trace_colo_vm_state_change("run", "stop");
    /*
     * failover request bh could be called after
     * vm_stop_force_state so we check failover_request_is_active() again.
     */
    if (failover_request_is_active()) {
        ret = -1;
        goto out;
    }

    /* we call this api although this may do nothing on primary side */
    qemu_mutex_lock_iothread();
    bdrv_do_checkpoint_all(&local_err);
    qemu_mutex_unlock_iothread();
    if (local_err) {
        error_report_err(local_err);
        ret = -1;
        goto out;
    }

    ret = colo_put_cmd(s->to_dst_file, COLO_COMMAND_VMSTATE_SEND);
    if (ret < 0) {
        goto out;
    }

    qemu_mutex_lock_iothread();
    /* Note: device state is saved into buffer */
    ret = qemu_save_device_state(trans);
    if (ret < 0) {
        error_report("save device state error\n");
        qemu_mutex_unlock_iothread();
        goto out;
    }
    qemu_fflush(trans);
    qemu_save_ram_precopy(s->to_dst_file);
    qemu_mutex_unlock_iothread();

    /* we send the total size of the vmstate first */
    size = qsb_get_length(buffer);
    ret = colo_put_cmd_value(s->to_dst_file, COLO_COMMAND_VMSTATE_SIZE, size);
    if (ret < 0) {
        goto out;
    }

    qsb_put_buffer(s->to_dst_file, buffer, size);
    qemu_fflush(s->to_dst_file);
    ret = qemu_file_get_error(s->to_dst_file);
    if (ret < 0) {
        goto out;
    }

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

    qemu_release_default_filters_packets();

    if (colo_shutdown) {
        qemu_mutex_lock_iothread();
        bdrv_stop_replication_all(false, NULL);
        trace_colo_stop_block_replication("shutdown");
        qemu_mutex_unlock_iothread();
        colo_put_cmd(s->to_dst_file, COLO_COMMAND_GUEST_SHUTDOWN);
        qemu_fflush(s->to_dst_file);
        colo_shutdown_requested = 0;
        qemu_system_shutdown_request_core();
        /* Fix me: Just let the colo thread exit ? */
        qemu_thread_exit(0);
    }

    ret = 0;
    /* Resume primary guest */
    qemu_mutex_lock_iothread();
    vm_start();
    qemu_mutex_unlock_iothread();
    trace_colo_vm_state_change("stop", "run");

out:
    if (trans) {
        qemu_fclose(trans);
    }

    return ret;
}

static int colo_prepare_before_save(MigrationState *s)
{
    int ret;
    /* Disable block migration */
    s->params.blk = 0;
    s->params.shared = 0;
    qemu_savevm_state_begin(s->to_dst_file, &s->params);
    ret = qemu_file_get_error(s->to_dst_file);
    if (ret < 0) {
        error_report("save vm state begin error\n");
        return ret;
    }
    return 0;
}

static int colo_init_buffer_filters(void)
{
    if (!qemu_netdev_support_netfilter()) {
        return -EPERM;
    }
    /* Begin to buffer packets that sent by VM */
    qemu_set_default_filters_status(true);

    return 0;
}

static void colo_process_checkpoint(MigrationState *s)
{
    QEMUSizedBuffer *buffer = NULL;
    int64_t current_time, checkpoint_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    int ret = 0;
    Error *local_err = NULL;

    failover_init_state();
    ret = colo_init_buffer_filters();
    if (ret < 0) {
        goto out;
    }
    s->rp_state.from_dst_file = qemu_file_get_return_path(s->to_dst_file);
    if (!s->rp_state.from_dst_file) {
        ret = -EINVAL;
        error_report("Open QEMUFile from_dst_file failed");
        goto out;
    }

    ret = colo_prepare_before_save(s);
    if (ret < 0) {
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

    buffer = qsb_create(NULL, COLO_BUFFER_BASE_SIZE);
    if (buffer == NULL) {
        ret = -ENOMEM;
        error_report("Failed to allocate colo buffer!");
        goto out;
    }

    qemu_mutex_lock_iothread();
    /* start block replication */
    bdrv_start_replication_all(REPLICATION_MODE_PRIMARY, &local_err);
    if (local_err) {
        qemu_mutex_unlock_iothread();
        error_report_err(local_err);
        ret = -EINVAL;
        goto out;
    }
    trace_colo_start_block_replication();
    vm_start();
    qemu_mutex_unlock_iothread();
    trace_colo_vm_state_change("stop", "run");

    ret = global_state_store();
    if (ret < 0) {
        goto out;
    }

    while (s->state == MIGRATION_STATUS_COLO) {
        if (failover_request_is_active()) {
            error_report("failover request");
            goto out;
        }

        current_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
        if ((current_time - checkpoint_time <
            s->parameters[MIGRATION_PARAMETER_X_CHECKPOINT_DELAY]) &&
            !colo_shutdown_requested) {
            int64_t delay_ms;

            delay_ms = s->parameters[MIGRATION_PARAMETER_X_CHECKPOINT_DELAY] -
                       (current_time - checkpoint_time);
            g_usleep(delay_ms * 1000);
        }
        /* start a colo checkpoint */
        ret = colo_do_checkpoint_transaction(s, buffer);
        if (ret < 0) {
            goto out;
        }
        checkpoint_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    }

out:
    if (ret < 0 || (!ret && !failover_request_is_active())) {
        error_report("%s: %s", __func__, strerror(-ret));
        qapi_event_send_colo_exit(COLO_MODE_PRIMARY, COLO_EXIT_REASON_ERROR,
                                  true, strerror(-ret), NULL);
    } else {
        qapi_event_send_colo_exit(COLO_MODE_PRIMARY, COLO_EXIT_REASON_REQUEST,
                                  false, NULL, NULL);
    }

    qsb_free(buffer);
    buffer = NULL;

    /* Hope this not to be too long to loop here */
    while (failover_get_state() != FAILOVER_STATUS_COMPLETED) {
        ;
    }
    /*
    * Must be called after failover BH is completed,
    * Or the failover BH may shutdown the wrong fd, that
    * re-used by other thread after we release here.
    */
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
    case COLO_COMMAND_GUEST_SHUTDOWN:
        qemu_mutex_lock_iothread();
        vm_stop_force_state(RUN_STATE_COLO);
        bdrv_stop_replication_all(false, NULL);
        trace_colo_stop_block_replication("shutdown");
        qemu_system_shutdown_request_core();
        qemu_mutex_unlock_iothread();
        /* the main thread will exit and termiante the whole
        * process, do we need some cleanup?
        */
        qemu_thread_exit(0);
    default:
        return -EINVAL;
    }
}

static int colo_prepare_before_load(QEMUFile *f)
{
    int ret;

    ret = qemu_loadvm_state_begin(f);
    if (ret < 0) {
        error_report("load vm state begin error, ret=%d", ret);
        return ret;
    }
    return 0;
}

void *colo_process_incoming_thread(void *opaque)
{
    MigrationIncomingState *mis = opaque;
    QEMUFile *fb = NULL;
    QEMUSizedBuffer *buffer = NULL; /* Cache incoming device state */
    uint64_t  total_size;
    int ret = 0;
    uint64_t value;
    Error *local_err = NULL;

    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COLO);

    failover_init_state();

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

    ret = colo_init_ram_cache();
    if (ret < 0) {
        error_report("Failed to initialize ram cache");
        goto out;
    }

    buffer = qsb_create(NULL, COLO_BUFFER_BASE_SIZE);
    if (buffer == NULL) {
        error_report("Failed to allocate colo buffer!");
        goto out;
    }

    ret = colo_prepare_before_load(mis->from_src_file);
    if (ret < 0) {
        goto out;
    }

    qemu_mutex_lock_iothread();
    /* start block replication */
    bdrv_start_replication_all(REPLICATION_MODE_SECONDARY, &local_err);
    qemu_mutex_unlock_iothread();
    if (local_err) {
        error_report_err(local_err);
        goto out;
    }
    trace_colo_start_block_replication();

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

        if (failover_request_is_active()) {
            error_report("failover request");
            goto out;
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

        ret = qemu_load_ram_state(mis->from_src_file);
        if (ret < 0) {
            error_report("load ram state error");
            goto out;
        }
        /* read the VM state total size first */
        ret = colo_get_cmd_value(mis->from_src_file,
                                 COLO_COMMAND_VMSTATE_SIZE, &value);
        if (ret < 0) {
            error_report("%s: Failed to get vmstate size", __func__);
            goto out;
        }

        /* read vm device state into colo buffer */
        total_size = qsb_fill_buffer(buffer, mis->from_src_file, value);
        if (total_size != value) {
            error_report("Got %lu VMState data, less than expected %lu",
                         total_size, value);
            ret = -EINVAL;
            goto out;
        }

        ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_VMSTATE_RECEIVED);
        if (ret < 0) {
            goto out;
        }

        /* open colo buffer for read */
        fb = qemu_bufopen("r", buffer);
        if (!fb) {
            error_report("can't open colo buffer for read");
            goto out;
        }

        qemu_mutex_lock_iothread();
        qemu_system_reset(VMRESET_SILENT);
        vmstate_loading = true;
        colo_flush_ram_cache();
        ret = qemu_load_device_state(fb);
        if (ret < 0) {
            error_report("COLO: load device state failed\n");
            vmstate_loading = false;
            qemu_mutex_unlock_iothread();
            goto out;
        }
        /* discard colo disk buffer */
        bdrv_do_checkpoint_all(&local_err);
        if (local_err) {
            vmstate_loading = false;
            qemu_mutex_unlock_iothread();
            goto out;
        }

        vmstate_loading = false;
        qemu_mutex_unlock_iothread();

        if (failover_get_state() == FAILOVER_STATUS_RELAUNCH) {
            failover_set_state(FAILOVER_STATUS_RELAUNCH, FAILOVER_STATUS_NONE);
            failover_request_active(NULL);
            goto out;
        }

        ret = colo_put_cmd(mis->to_src_file, COLO_COMMAND_VMSTATE_LOADED);
        if (ret < 0) {
            goto out;
        }

        qemu_fclose(fb);
        fb = NULL;
    }

out:
    if (ret < 0 || (!ret && !failover_request_is_active())) {
        error_report("colo incoming thread will exit, detect error: %s",
                     strerror(-ret));
        qapi_event_send_colo_exit(COLO_MODE_SECONDARY, COLO_EXIT_REASON_ERROR,
                                  true, strerror(-ret), NULL);
    } else {
        qapi_event_send_colo_exit(COLO_MODE_SECONDARY, COLO_EXIT_REASON_REQUEST,
                                  false, NULL, NULL);
    }

    if (fb) {
        qemu_fclose(fb);
    }
    qsb_free(buffer);
    /* Here, we can ensure BH is hold the global lock, and will join colo
    * incoming thread, so here it is not necessary to lock here again,
    * or there will be a deadlock error.
    */
    colo_release_ram_cache();

    /* Hope this not to be too long to loop here */
    while (failover_get_state() != FAILOVER_STATUS_COMPLETED) {
        ;
    }
    /* Must be called after failover BH is completed */
    if (mis->to_src_file) {
        qemu_fclose(mis->to_src_file);
    }
    migration_incoming_exit_colo();

    return NULL;
}
