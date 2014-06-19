/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "config-host.h"
#include "qemu-common.h"
#include "hw/boards.h"
#include "hw/hw.h"
#include "hw/qdev.h"
#include "net/net.h"
#include "monitor/monitor.h"
#include "sysemu/sysemu.h"
#include "qemu/timer.h"
#include "audio/audio.h"
#include "migration/migration.h"
#include "qemu/sockets.h"
#include "qemu/queue.h"
#include "sysemu/cpus.h"
#include "exec/memory.h"
#include "qmp-commands.h"
#include "trace.h"
#include "qemu/bitops.h"
#include "qemu/iov.h"
#include "block/snapshot.h"
#include "block/qapi.h"


#ifndef ETH_P_RARP
#define ETH_P_RARP 0x8035
#endif
#define ARP_HTYPE_ETH 0x0001
#define ARP_PTYPE_IP 0x0800
#define ARP_OP_REQUEST_REV 0x3

static int announce_self_create(uint8_t *buf,
                                uint8_t *mac_addr)
{
    /* Ethernet header. */
    memset(buf, 0xff, 6);         /* destination MAC addr */
    memcpy(buf + 6, mac_addr, 6); /* source MAC addr */
    *(uint16_t *)(buf + 12) = htons(ETH_P_RARP); /* ethertype */

    /* RARP header. */
    *(uint16_t *)(buf + 14) = htons(ARP_HTYPE_ETH); /* hardware addr space */
    *(uint16_t *)(buf + 16) = htons(ARP_PTYPE_IP); /* protocol addr space */
    *(buf + 18) = 6; /* hardware addr length (ethernet) */
    *(buf + 19) = 4; /* protocol addr length (IPv4) */
    *(uint16_t *)(buf + 20) = htons(ARP_OP_REQUEST_REV); /* opcode */
    memcpy(buf + 22, mac_addr, 6); /* source hw addr */
    memset(buf + 28, 0x00, 4);     /* source protocol addr */
    memcpy(buf + 32, mac_addr, 6); /* target hw addr */
    memset(buf + 38, 0x00, 4);     /* target protocol addr */

    /* Padding to get up to 60 bytes (ethernet min packet size, minus FCS). */
    memset(buf + 42, 0x00, 18);

    return 60; /* len (FCS will be added by hardware) */
}

static void qemu_announce_self_iter(NICState *nic, void *opaque)
{
    uint8_t buf[60];
    int len;

    trace_qemu_announce_self_iter(qemu_ether_ntoa(&nic->conf->macaddr));
    len = announce_self_create(buf, nic->conf->macaddr.a);

    qemu_send_packet_raw(qemu_get_queue(nic), buf, len);
}


static void qemu_announce_self_once(void *opaque)
{
    static int count = SELF_ANNOUNCE_ROUNDS;
    QEMUTimer *timer = *(QEMUTimer **)opaque;

    qemu_foreach_nic(qemu_announce_self_iter, NULL);

    if (--count) {
        /* delay 50ms, 150ms, 250ms, ... */
        timer_mod(timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                  self_announce_delay(count));
    } else {
            timer_del(timer);
            timer_free(timer);
    }
}

void qemu_announce_self(void)
{
    static QEMUTimer *timer;
    timer = timer_new_ms(QEMU_CLOCK_REALTIME, qemu_announce_self_once, &timer);
    qemu_announce_self_once(&timer);
}

/***********************************************************/
/* savevm/loadvm support */

static ssize_t block_writev_buffer(void *opaque, struct iovec *iov, int iovcnt,
                                   int64_t pos)
{
    int ret;
    QEMUIOVector qiov;

    qemu_iovec_init_external(&qiov, iov, iovcnt);
    ret = bdrv_writev_vmstate(opaque, &qiov, pos);
    if (ret < 0) {
        return ret;
    }

    return qiov.size;
}

static int block_put_buffer(void *opaque, const uint8_t *buf,
                           int64_t pos, int size)
{
    bdrv_save_vmstate(opaque, buf, pos, size);
    return size;
}

static int block_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    return bdrv_load_vmstate(opaque, buf, pos, size);
}

static int bdrv_fclose(void *opaque)
{
    return bdrv_flush(opaque);
}

static const QEMUFileOps bdrv_read_ops = {
    .get_buffer = block_get_buffer,
    .close =      bdrv_fclose
};

static const QEMUFileOps bdrv_write_ops = {
    .put_buffer     = block_put_buffer,
    .writev_buffer  = block_writev_buffer,
    .close          = bdrv_fclose
};

static QEMUFile *qemu_fopen_bdrv(BlockDriverState *bs, int is_writable)
{
    if (is_writable) {
        return qemu_fopen_ops(bs, &bdrv_write_ops);
    }
    return qemu_fopen_ops(bs, &bdrv_read_ops);
}


/* QEMUFile timer support.
 * Not in qemu-file.c to not add qemu-timer.c as dependency to qemu-file.c
 */

void timer_put(QEMUFile *f, QEMUTimer *ts)
{
    uint64_t expire_time;

    expire_time = timer_expire_time_ns(ts);
    qemu_put_be64(f, expire_time);
}

void timer_get(QEMUFile *f, QEMUTimer *ts)
{
    uint64_t expire_time;

    expire_time = qemu_get_be64(f);
    if (expire_time != -1) {
        timer_mod_ns(ts, expire_time);
    } else {
        timer_del(ts);
    }
}


/* VMState timer support.
 * Not in vmstate.c to not add qemu-timer.c as dependency to vmstate.c
 */

static int get_timer(QEMUFile *f, void *pv, size_t size)
{
    QEMUTimer *v = pv;
    timer_get(f, v);
    return 0;
}

static void put_timer(QEMUFile *f, void *pv, size_t size)
{
    QEMUTimer *v = pv;
    timer_put(f, v);
}

const VMStateInfo vmstate_info_timer = {
    .name = "timer",
    .get  = get_timer,
    .put  = put_timer,
};


typedef struct CompatEntry {
    char idstr[256];
    int instance_id;
} CompatEntry;

typedef struct SaveStateEntry {
    QTAILQ_ENTRY(SaveStateEntry) entry;
    char idstr[256];
    int instance_id;
    int alias_id;
    int version_id;
    int section_id;
    SaveVMHandlers *ops;
    const VMStateDescription *vmsd;
    void *opaque;
    CompatEntry *compat;
    int is_ram;
} SaveStateEntry;


static QTAILQ_HEAD(savevm_handlers, SaveStateEntry) savevm_handlers =
    QTAILQ_HEAD_INITIALIZER(savevm_handlers);
static int global_section_id;

static void dump_vmstate_vmsd(FILE *out_file,
                              const VMStateDescription *vmsd, int indent,
                              bool is_subsection);

static void dump_vmstate_vmsf(FILE *out_file, const VMStateField *field,
                              int indent)
{
    fprintf(out_file, "%*s{\n", indent, "");
    indent += 2;
    fprintf(out_file, "%*s\"field\": \"%s\",\n", indent, "", field->name);
    fprintf(out_file, "%*s\"version_id\": %d,\n", indent, "",
            field->version_id);
    fprintf(out_file, "%*s\"field_exists\": %s,\n", indent, "",
            field->field_exists ? "true" : "false");
    fprintf(out_file, "%*s\"size\": %zu", indent, "", field->size);
    if (field->vmsd != NULL) {
        fprintf(out_file, ",\n");
        dump_vmstate_vmsd(out_file, field->vmsd, indent, false);
    }
    fprintf(out_file, "\n%*s}", indent - 2, "");
}

static void dump_vmstate_vmss(FILE *out_file,
                              const VMStateSubsection *subsection,
                              int indent)
{
    if (subsection->vmsd != NULL) {
        dump_vmstate_vmsd(out_file, subsection->vmsd, indent, true);
    }
}

static void dump_vmstate_vmsd(FILE *out_file,
                              const VMStateDescription *vmsd, int indent,
                              bool is_subsection)
{
    if (is_subsection) {
        fprintf(out_file, "%*s{\n", indent, "");
    } else {
        fprintf(out_file, "%*s\"%s\": {\n", indent, "", "Description");
    }
    indent += 2;
    fprintf(out_file, "%*s\"name\": \"%s\",\n", indent, "", vmsd->name);
    fprintf(out_file, "%*s\"version_id\": %d,\n", indent, "",
            vmsd->version_id);
    fprintf(out_file, "%*s\"minimum_version_id\": %d", indent, "",
            vmsd->minimum_version_id);
    if (vmsd->fields != NULL) {
        const VMStateField *field = vmsd->fields;
        bool first;

        fprintf(out_file, ",\n%*s\"Fields\": [\n", indent, "");
        first = true;
        while (field->name != NULL) {
            if (field->flags & VMS_MUST_EXIST) {
                /* Ignore VMSTATE_VALIDATE bits; these don't get migrated */
                field++;
                continue;
            }
            if (!first) {
                fprintf(out_file, ",\n");
            }
            dump_vmstate_vmsf(out_file, field, indent + 2);
            field++;
            first = false;
        }
        fprintf(out_file, "\n%*s]", indent, "");
    }
    if (vmsd->subsections != NULL) {
        const VMStateSubsection *subsection = vmsd->subsections;
        bool first;

        fprintf(out_file, ",\n%*s\"Subsections\": [\n", indent, "");
        first = true;
        while (subsection->vmsd != NULL) {
            if (!first) {
                fprintf(out_file, ",\n");
            }
            dump_vmstate_vmss(out_file, subsection, indent + 2);
            subsection++;
            first = false;
        }
        fprintf(out_file, "\n%*s]", indent, "");
    }
    fprintf(out_file, "\n%*s}", indent - 2, "");
}

static void dump_machine_type(FILE *out_file)
{
    MachineClass *mc;

    mc = MACHINE_GET_CLASS(current_machine);

    fprintf(out_file, "  \"vmschkmachine\": {\n");
    fprintf(out_file, "    \"Name\": \"%s\"\n", mc->name);
    fprintf(out_file, "  },\n");
}

void dump_vmstate_json_to_file(FILE *out_file)
{
    GSList *list, *elt;
    bool first;

    fprintf(out_file, "{\n");
    dump_machine_type(out_file);

    first = true;
    list = object_class_get_list(TYPE_DEVICE, true);
    for (elt = list; elt; elt = elt->next) {
        DeviceClass *dc = OBJECT_CLASS_CHECK(DeviceClass, elt->data,
                                             TYPE_DEVICE);
        const char *name;
        int indent = 2;

        if (!dc->vmsd) {
            continue;
        }

        if (!first) {
            fprintf(out_file, ",\n");
        }
        name = object_class_get_name(OBJECT_CLASS(dc));
        fprintf(out_file, "%*s\"%s\": {\n", indent, "", name);
        indent += 2;
        fprintf(out_file, "%*s\"Name\": \"%s\",\n", indent, "", name);
        fprintf(out_file, "%*s\"version_id\": %d,\n", indent, "",
                dc->vmsd->version_id);
        fprintf(out_file, "%*s\"minimum_version_id\": %d,\n", indent, "",
                dc->vmsd->minimum_version_id);

        dump_vmstate_vmsd(out_file, dc->vmsd, indent, false);

        fprintf(out_file, "\n%*s}", indent - 2, "");
        first = false;
    }
    fprintf(out_file, "\n}\n");
    fclose(out_file);
}

static int calculate_new_instance_id(const char *idstr)
{
    SaveStateEntry *se;
    int instance_id = 0;

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (strcmp(idstr, se->idstr) == 0
            && instance_id <= se->instance_id) {
            instance_id = se->instance_id + 1;
        }
    }
    return instance_id;
}

static int calculate_compat_instance_id(const char *idstr)
{
    SaveStateEntry *se;
    int instance_id = 0;

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!se->compat) {
            continue;
        }

        if (strcmp(idstr, se->compat->idstr) == 0
            && instance_id <= se->compat->instance_id) {
            instance_id = se->compat->instance_id + 1;
        }
    }
    return instance_id;
}

/* TODO: Individual devices generally have very little idea about the rest
   of the system, so instance_id should be removed/replaced.
   Meanwhile pass -1 as instance_id if you do not already have a clearly
   distinguishing id for all instances of your device class. */
int register_savevm_live(DeviceState *dev,
                         const char *idstr,
                         int instance_id,
                         int version_id,
                         SaveVMHandlers *ops,
                         void *opaque)
{
    SaveStateEntry *se;

    se = g_malloc0(sizeof(SaveStateEntry));
    se->version_id = version_id;
    se->section_id = global_section_id++;
    se->ops = ops;
    se->opaque = opaque;
    se->vmsd = NULL;
    /* if this is a live_savem then set is_ram */
    if (ops->save_live_setup != NULL) {
        se->is_ram = 1;
    }

    if (dev) {
        char *id = qdev_get_dev_path(dev);
        if (id) {
            pstrcpy(se->idstr, sizeof(se->idstr), id);
            pstrcat(se->idstr, sizeof(se->idstr), "/");
            g_free(id);

            se->compat = g_malloc0(sizeof(CompatEntry));
            pstrcpy(se->compat->idstr, sizeof(se->compat->idstr), idstr);
            se->compat->instance_id = instance_id == -1 ?
                         calculate_compat_instance_id(idstr) : instance_id;
            instance_id = -1;
        }
    }
    pstrcat(se->idstr, sizeof(se->idstr), idstr);

    if (instance_id == -1) {
        se->instance_id = calculate_new_instance_id(se->idstr);
    } else {
        se->instance_id = instance_id;
    }
    assert(!se->compat || se->instance_id == 0);
    /* add at the end of list */
    QTAILQ_INSERT_TAIL(&savevm_handlers, se, entry);
    return 0;
}

int register_savevm(DeviceState *dev,
                    const char *idstr,
                    int instance_id,
                    int version_id,
                    SaveStateHandler *save_state,
                    LoadStateHandler *load_state,
                    void *opaque)
{
    SaveVMHandlers *ops = g_malloc0(sizeof(SaveVMHandlers));
    ops->save_state = save_state;
    ops->load_state = load_state;
    return register_savevm_live(dev, idstr, instance_id, version_id,
                                ops, opaque);
}

void unregister_savevm(DeviceState *dev, const char *idstr, void *opaque)
{
    SaveStateEntry *se, *new_se;
    char id[256] = "";

    if (dev) {
        char *path = qdev_get_dev_path(dev);
        if (path) {
            pstrcpy(id, sizeof(id), path);
            pstrcat(id, sizeof(id), "/");
            g_free(path);
        }
    }
    pstrcat(id, sizeof(id), idstr);

    QTAILQ_FOREACH_SAFE(se, &savevm_handlers, entry, new_se) {
        if (strcmp(se->idstr, id) == 0 && se->opaque == opaque) {
            QTAILQ_REMOVE(&savevm_handlers, se, entry);
            if (se->compat) {
                g_free(se->compat);
            }
            g_free(se->ops);
            g_free(se);
        }
    }
}

int vmstate_register_with_alias_id(DeviceState *dev, int instance_id,
                                   const VMStateDescription *vmsd,
                                   void *opaque, int alias_id,
                                   int required_for_version)
{
    SaveStateEntry *se;

    /* If this triggers, alias support can be dropped for the vmsd. */
    assert(alias_id == -1 || required_for_version >= vmsd->minimum_version_id);

    se = g_malloc0(sizeof(SaveStateEntry));
    se->version_id = vmsd->version_id;
    se->section_id = global_section_id++;
    se->opaque = opaque;
    se->vmsd = vmsd;
    se->alias_id = alias_id;

    if (dev) {
        char *id = qdev_get_dev_path(dev);
        if (id) {
            pstrcpy(se->idstr, sizeof(se->idstr), id);
            pstrcat(se->idstr, sizeof(se->idstr), "/");
            g_free(id);

            se->compat = g_malloc0(sizeof(CompatEntry));
            pstrcpy(se->compat->idstr, sizeof(se->compat->idstr), vmsd->name);
            se->compat->instance_id = instance_id == -1 ?
                         calculate_compat_instance_id(vmsd->name) : instance_id;
            instance_id = -1;
        }
    }
    pstrcat(se->idstr, sizeof(se->idstr), vmsd->name);

    if (instance_id == -1) {
        se->instance_id = calculate_new_instance_id(se->idstr);
    } else {
        se->instance_id = instance_id;
    }
    assert(!se->compat || se->instance_id == 0);
    /* add at the end of list */
    QTAILQ_INSERT_TAIL(&savevm_handlers, se, entry);
    return 0;
}

void vmstate_unregister(DeviceState *dev, const VMStateDescription *vmsd,
                        void *opaque)
{
    SaveStateEntry *se, *new_se;

    QTAILQ_FOREACH_SAFE(se, &savevm_handlers, entry, new_se) {
        if (se->vmsd == vmsd && se->opaque == opaque) {
            QTAILQ_REMOVE(&savevm_handlers, se, entry);
            if (se->compat) {
                g_free(se->compat);
            }
            g_free(se);
        }
    }
}

static int vmstate_load(QEMUFile *f, SaveStateEntry *se, int version_id)
{
    trace_vmstate_load(se->idstr, se->vmsd ? se->vmsd->name : "(old)");
    if (!se->vmsd) {         /* Old style */
        return se->ops->load_state(f, se->opaque, version_id);
    }
    return vmstate_load_state(f, se->vmsd, se->opaque, version_id);
}

static void vmstate_save_old_style(QEMUFile *f, SaveStateEntry *se, QJSON *vmdesc)
{
    int64_t old_offset, size;

    old_offset = qemu_ftell_fast(f);
    se->ops->save_state(f, se->opaque);
    size = qemu_ftell_fast(f) - old_offset;

    if (vmdesc) {
        json_prop_int(vmdesc, "size", size);
        json_start_array(vmdesc, "fields");
        json_start_object(vmdesc, NULL);
        json_prop_str(vmdesc, "name", "data");
        json_prop_int(vmdesc, "size", size);
        json_prop_str(vmdesc, "type", "buffer");
        json_end_object(vmdesc);
        json_end_array(vmdesc);
    }
}

static void vmstate_save(QEMUFile *f, SaveStateEntry *se, QJSON *vmdesc)
{
    trace_vmstate_save(se->idstr, se->vmsd ? se->vmsd->name : "(old)");
    if (!se->vmsd) {
        vmstate_save_old_style(f, se, vmdesc);
        return;
    }
    vmstate_save_state(f, se->vmsd, se->opaque, vmdesc);
}


/* Send a 'QEMU_VM_COMMAND' type element with the command
 * and associated data.
 */
void qemu_savevm_command_send(QEMUFile *f,
                              enum qemu_vm_cmd command,
                              uint16_t len,
                              uint8_t *data)
{
    uint32_t tmp = (uint16_t)command;
    qemu_put_byte(f, QEMU_VM_COMMAND);
    qemu_put_be16(f, tmp);
    qemu_put_be16(f, len);
    if (len) {
        qemu_put_buffer(f, data, len);
    }
    qemu_fflush(f);
}

void qemu_savevm_send_ping(QEMUFile *f, uint32_t value)
{
    uint32_t buf;

    trace_savevm_send_ping(value);
    buf = cpu_to_be32(value);
    qemu_savevm_command_send(f, MIG_CMD_PING, 4, (uint8_t *)&buf);
}

void qemu_savevm_send_open_return_path(QEMUFile *f)
{
    qemu_savevm_command_send(f, MIG_CMD_OPEN_RETURN_PATH, 0, NULL);
}

/* Send prior to any postcopy transfer */
void qemu_savevm_send_postcopy_advise(QEMUFile *f)
{
    uint64_t tmp[2];
    tmp[0] = cpu_to_be64(getpagesize());
    tmp[1] = cpu_to_be64(1ul << qemu_target_page_bits());

    trace_qemu_savevm_send_postcopy_advise();
    qemu_savevm_command_send(f, MIG_CMD_POSTCOPY_ADVISE, 16, (uint8_t *)tmp);
}

/* Prior to running, to cause pages that have been dirtied after precopy
 * started to be discarded on the destination.
 * CMD_POSTCOPY_RAM_DISCARD consist of:
 *  3 byte header (filled in by qemu_savevm_send_postcopy_ram_discard)
 *      byte   version (0)
 *      byte   offset to be subtracted from each page address to deal with
 *             RAMBlocks that don't start on a mask word boundary.
 *      byte   Length of name field
 *  n x byte   RAM block name (NOT 0 terminated)
 *  n x
 *      be64   Page addresses for start of an invalidation range
 *      be32   mask of 32 pages, '1' to discard'
 *
 *  Hopefully this is pretty sparse so we don't get too many entries,
 *  and using the mask should deal with most pagesize differences
 *  just ending up as a single full mask
 *
 * The mask is always 32bits irrespective of the long size
 *
 *  name:  RAMBlock name that these entries are part of
 *  len: Number of page entries
 *  addrlist: 'len' addresses
 *  masklist: 'len' masks (corresponding to the addresses)
 */
void qemu_savevm_send_postcopy_ram_discard(QEMUFile *f, const char *name,
                                           uint16_t len, uint8_t offset,
                                           uint64_t *addrlist,
                                           uint32_t *masklist)
{
    uint8_t *buf;
    uint16_t tmplen;
    uint16_t t;

    trace_qemu_savevm_send_postcopy_ram_discard();
    buf = g_malloc0(len*12 + strlen(name) + 3);
    buf[0] = 0; /* Version */
    buf[1] = offset;
    assert(strlen(name) < 256);
    buf[2] = strlen(name);
    memcpy(buf+3, name, strlen(name));
    tmplen = 3+strlen(name);

    for (t = 0; t < len; t++) {
        cpu_to_be64w((uint64_t *)(buf + tmplen), addrlist[t]);
        tmplen += 8;
        cpu_to_be32w((uint32_t *)(buf + tmplen), masklist[t]);
        tmplen += 4;
    }
    qemu_savevm_command_send(f, MIG_CMD_POSTCOPY_RAM_DISCARD, tmplen, buf);
    g_free(buf);
}

/* Get the destination into a state where it can receive postcopy data. */
void qemu_savevm_send_postcopy_listen(QEMUFile *f)
{
    trace_savevm_send_postcopy_listen();
    qemu_savevm_command_send(f, MIG_CMD_POSTCOPY_LISTEN, 0, NULL);
}

/* Kick the destination into running */
void qemu_savevm_send_postcopy_run(QEMUFile *f)
{
    trace_savevm_send_postcopy_run();
    qemu_savevm_command_send(f, MIG_CMD_POSTCOPY_RUN, 0, NULL);
}

/* End of postcopy - with a status byte; 0 is good, anything else is a fail */
void qemu_savevm_send_postcopy_end(QEMUFile *f, uint8_t status)
{
    trace_savevm_send_postcopy_end();
    qemu_savevm_command_send(f, MIG_CMD_POSTCOPY_END, 1, &status);
}

bool qemu_savevm_state_blocked(Error **errp)
{
    SaveStateEntry *se;

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (se->vmsd && se->vmsd->unmigratable) {
            error_setg(errp, "State blocked by non-migratable device '%s'",
                       se->idstr);
            return true;
        }
    }
    return false;
}

void qemu_savevm_state_header(QEMUFile *f)
{
    trace_savevm_state_header();
    qemu_put_be32(f, QEMU_VM_FILE_MAGIC);
    qemu_put_be32(f, QEMU_VM_FILE_VERSION);
}

void qemu_savevm_state_begin(QEMUFile *f,
                             const MigrationParams *params)
{
    SaveStateEntry *se;
    int ret;

    trace_savevm_state_begin();
    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!se->ops || !se->ops->set_params) {
            continue;
        }
        se->ops->set_params(params, se->opaque);
    }

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        int len;

        if (!se->ops || !se->ops->save_live_setup) {
            continue;
        }
        if (se->ops && se->ops->is_active) {
            if (!se->ops->is_active(se->opaque)) {
                continue;
            }
        }
        /* Section type */
        qemu_put_byte(f, QEMU_VM_SECTION_START);
        qemu_put_be32(f, se->section_id);

        /* ID string */
        len = strlen(se->idstr);
        qemu_put_byte(f, len);
        qemu_put_buffer(f, (uint8_t *)se->idstr, len);

        qemu_put_be32(f, se->instance_id);
        qemu_put_be32(f, se->version_id);

        ret = se->ops->save_live_setup(f, se->opaque);
        if (ret < 0) {
            qemu_file_set_error(f, ret);
            break;
        }
    }
}

/*
 * this function has three return values:
 *   negative: there was one error, and we have -errno.
 *   0 : We haven't finished, caller have to go again
 *   1 : We have finished, we can go to complete phase
 */
int qemu_savevm_state_iterate(QEMUFile *f)
{
    SaveStateEntry *se;
    int ret = 1;

    trace_savevm_state_iterate();
    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!se->ops || !se->ops->save_live_iterate) {
            continue;
        }
        if (se->ops && se->ops->is_active) {
            if (!se->ops->is_active(se->opaque)) {
                continue;
            }
        }
        if (qemu_file_rate_limit(f)) {
            return 0;
        }
        trace_savevm_section_start(se->idstr, se->section_id);
        /* Section type */
        qemu_put_byte(f, QEMU_VM_SECTION_PART);
        qemu_put_be32(f, se->section_id);

        ret = se->ops->save_live_iterate(f, se->opaque);
        trace_savevm_section_end(se->idstr, se->section_id, ret);

        if (ret < 0) {
            qemu_file_set_error(f, ret);
        }
        if (ret <= 0) {
            /* Do not proceed to the next vmstate before this one reported
               completion of the current stage. This serializes the migration
               and reduces the probability that a faster changing state is
               synchronized over and over again. */
            break;
        }
    }
    return ret;
}

void qemu_savevm_state_complete(QEMUFile *f)
{
    QJSON *vmdesc;
    int vmdesc_len;
    SaveStateEntry *se;
    int ret;

    trace_savevm_state_complete();

    cpu_synchronize_all_states();

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!se->ops || !se->ops->save_live_complete) {
            continue;
        }
        if (se->ops && se->ops->is_active) {
            if (!se->ops->is_active(se->opaque)) {
                continue;
            }
        }
        trace_savevm_section_start(se->idstr, se->section_id);
        /* Section type */
        qemu_put_byte(f, QEMU_VM_SECTION_END);
        qemu_put_be32(f, se->section_id);

        ret = se->ops->save_live_complete(f, se->opaque);
        trace_savevm_section_end(se->idstr, se->section_id, ret);
        if (ret < 0) {
            qemu_file_set_error(f, ret);
            return;
        }
    }

    vmdesc = qjson_new();
    json_prop_int(vmdesc, "page_size", TARGET_PAGE_SIZE);
    json_start_array(vmdesc, "devices");
    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        int len;

        if ((!se->ops || !se->ops->save_state) && !se->vmsd) {
            continue;
        }
        trace_savevm_section_start(se->idstr, se->section_id);

        json_start_object(vmdesc, NULL);
        json_prop_str(vmdesc, "name", se->idstr);
        json_prop_int(vmdesc, "instance_id", se->instance_id);

        /* Section type */
        qemu_put_byte(f, QEMU_VM_SECTION_FULL);
        qemu_put_be32(f, se->section_id);

        /* ID string */
        len = strlen(se->idstr);
        qemu_put_byte(f, len);
        qemu_put_buffer(f, (uint8_t *)se->idstr, len);

        qemu_put_be32(f, se->instance_id);
        qemu_put_be32(f, se->version_id);

        vmstate_save(f, se, vmdesc);

        json_end_object(vmdesc);
        trace_savevm_section_end(se->idstr, se->section_id, 0);
    }

    qemu_put_byte(f, QEMU_VM_EOF);

    json_end_array(vmdesc);
    qjson_finish(vmdesc);
    vmdesc_len = strlen(qjson_get_str(vmdesc));

    qemu_put_byte(f, QEMU_VM_VMDESCRIPTION);
    qemu_put_be32(f, vmdesc_len);
    qemu_put_buffer(f, (uint8_t *)qjson_get_str(vmdesc), vmdesc_len);
    object_unref(OBJECT(vmdesc));

    qemu_fflush(f);
}

uint64_t qemu_savevm_state_pending(QEMUFile *f, uint64_t max_size)
{
    SaveStateEntry *se;
    uint64_t ret = 0;

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!se->ops || !se->ops->save_live_pending) {
            continue;
        }
        if (se->ops && se->ops->is_active) {
            if (!se->ops->is_active(se->opaque)) {
                continue;
            }
        }
        ret += se->ops->save_live_pending(f, se->opaque, max_size);
    }
    return ret;
}

void qemu_savevm_state_cancel(void)
{
    SaveStateEntry *se;

    trace_savevm_state_cancel();
    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (se->ops && se->ops->cancel) {
            se->ops->cancel(se->opaque);
        }
    }
}

static int qemu_savevm_state(QEMUFile *f)
{
    int ret;
    MigrationParams params = {
        .blk = 0,
        .shared = 0
    };

    if (qemu_savevm_state_blocked(NULL)) {
        return -EINVAL;
    }

    qemu_mutex_unlock_iothread();
    qemu_savevm_state_header(f);
    qemu_savevm_state_begin(f, &params);
    qemu_mutex_lock_iothread();

    while (qemu_file_get_error(f) == 0) {
        if (qemu_savevm_state_iterate(f) > 0) {
            break;
        }
    }

    ret = qemu_file_get_error(f);
    if (ret == 0) {
        qemu_savevm_state_complete(f);
        ret = qemu_file_get_error(f);
    }
    if (ret != 0) {
        qemu_savevm_state_cancel();
    }
    return ret;
}

static int qemu_save_device_state(QEMUFile *f)
{
    SaveStateEntry *se;

    qemu_put_be32(f, QEMU_VM_FILE_MAGIC);
    qemu_put_be32(f, QEMU_VM_FILE_VERSION);

    cpu_synchronize_all_states();

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        int len;

        if (se->is_ram) {
            continue;
        }
        if ((!se->ops || !se->ops->save_state) && !se->vmsd) {
            continue;
        }

        /* Section type */
        qemu_put_byte(f, QEMU_VM_SECTION_FULL);
        qemu_put_be32(f, se->section_id);

        /* ID string */
        len = strlen(se->idstr);
        qemu_put_byte(f, len);
        qemu_put_buffer(f, (uint8_t *)se->idstr, len);

        qemu_put_be32(f, se->instance_id);
        qemu_put_be32(f, se->version_id);

        vmstate_save(f, se, NULL);
    }

    qemu_put_byte(f, QEMU_VM_EOF);

    return qemu_file_get_error(f);
}

static SaveStateEntry *find_se(const char *idstr, int instance_id)
{
    SaveStateEntry *se;

    QTAILQ_FOREACH(se, &savevm_handlers, entry) {
        if (!strcmp(se->idstr, idstr) &&
            (instance_id == se->instance_id ||
             instance_id == se->alias_id))
            return se;
        /* Migrating from an older version? */
        if (strstr(se->idstr, idstr) && se->compat) {
            if (!strcmp(se->compat->idstr, idstr) &&
                (instance_id == se->compat->instance_id ||
                 instance_id == se->alias_id))
                return se;
        }
    }
    return NULL;
}

/* ORable flags that control the (potentially nested) loadvm_state loops */
enum LoadVMExitCodes {
    /* Quit the loop level that received this command */
    LOADVM_QUIT_LOOP     =  1,
    /* Quit this loop and our parent */
    LOADVM_QUIT_PARENT   =  2,
};

static int qemu_loadvm_state_main(QEMUFile *f, MigrationIncomingState *mis);

/* ------ incoming postcopy messages ------ */
/* 'advise' arrives before any transfers just to tell us that a postcopy
 * *might* happen - it might be skipped if precopy transferred everything
 * quickly.
 */
static int loadvm_postcopy_handle_advise(MigrationIncomingState *mis,
                                         uint64_t remote_hps,
                                         uint64_t remote_tps)
{
    PostcopyState ps = postcopy_state_get(mis);
    trace_loadvm_postcopy_handle_advise();
    if (ps != POSTCOPY_INCOMING_NONE) {
        error_report("CMD_POSTCOPY_ADVISE in wrong postcopy state (%d)", ps);
        return -1;
    }

    if (remote_hps != getpagesize())  {
        /*
         * Some combinations of mismatch are probably possible but it gets
         * a bit more complicated.  In particular we need to place whole
         * host pages on the dest at once, and we need to ensure that we
         * handle dirtying to make sure we never end up sending part of
         * a hostpage on it's own.
         */
        error_report("Postcopy needs matching host page sizes (s=%d d=%d)",
                     (int)remote_hps, getpagesize());
        return -1;
    }

    if (remote_tps != (1ul << qemu_target_page_bits())) {
        /*
         * Again, some differences could be dealt with, but for now keep it
         * simple.
         */
        error_report("Postcopy needs matching target page sizes (s=%d d=%d)",
                     (int)remote_tps, 1 << qemu_target_page_bits());
        return -1;
    }

    postcopy_state_set(mis, POSTCOPY_INCOMING_ADVISE);

    return 0;
}

/* After postcopy we will be told to throw some pages away since they're
 * dirty and will have to be demand fetched.  Must happen before CPU is
 * started.
 * There can be 0..many of these messages, each encoding multiple pages.
 * Bits set in the message represent a page in the source VMs bitmap, but
 * since the guest/target page sizes can be different on s/d then we have
 * to convert.
 */
static int loadvm_postcopy_ram_handle_discard(MigrationIncomingState *mis,
                                              uint16_t len)
{
    int tmp;
    unsigned int first_bit_offset;
    char ramid[256];
    PostcopyState ps = postcopy_state_get(mis);

    trace_loadvm_postcopy_ram_handle_discard();

    if (ps != POSTCOPY_INCOMING_ADVISE) {
        error_report("CMD_POSTCOPY_RAM_DISCARD in wrong postcopy state (%d)",
                     ps);
        return -1;
    }
    /* We're expecting a
     *    3 byte header,
     *    a RAM ID string
     *    then at least 1 12 byte chunks
    */
    if (len < 16) {
        error_report("CMD_POSTCOPY_RAM_DISCARD invalid length (%d)", len);
        return -1;
    }

    tmp = qemu_get_byte(mis->file);
    if (tmp != 0) {
        error_report("CMD_POSTCOPY_RAM_DISCARD invalid version (%d)", tmp);
        return -1;
    }
    first_bit_offset = qemu_get_byte(mis->file);

    if (qemu_get_counted_string(mis->file, ramid)) {
        error_report("CMD_POSTCOPY_RAM_DISCARD Failed to read RAMBlock ID");
        return -1;
    }

    len -= 3+strlen(ramid);
    if (len % 12) {
        error_report("CMD_POSTCOPY_RAM_DISCARD invalid length (%d)", len);
        return -1;
    }
    while (len) {
        uint64_t startaddr;
        uint32_t mask;
        /*
         * We now have pairs of address, mask
         *   Each word of mask is 32 bits, where each bit corresponds to one
         *   target page.
         *   RAMBlocks don't necessarily start on word boundaries,
         *   and the offset in the header indicates the offset into the 1st
         *   mask word that corresponds to the 1st page of the RAMBlock.
         */
        startaddr = qemu_get_be64(mis->file);
        mask = qemu_get_be32(mis->file);

        len -= 12;

        while (mask) {
            /* mask= .....?10...0 */
            /*             ^fs    */
            int firstset = ctz32(mask);

            /* tmp32=.....?11...1 */
            /*             ^fs    */
            uint32_t tmp32 = mask | ((((uint32_t)1)<<firstset)-1);

            /* mask= .?01..10...0 */
            /*         ^fz ^fs    */
            int firstzero = cto32(tmp32);

            if ((startaddr == 0) && (firstset < first_bit_offset)) {
                error_report("CMD_POSTCOPY_RAM_DISCARD bad data; bit set"
                               " prior to block; block=%s offset=%d"
                               " firstset=%d\n", ramid, first_bit_offset,
                               firstzero);
                return -1;
            }

            /*
             * we know there must be at least 1 bit set due to the loop entry
             * If there is no 0 firstzero will be 32
             */
            /* TODO - ram_discard_range gets added in a later patch
            int ret = ram_discard_range(mis, ramid,
                                startaddr + firstset - first_bit_offset,
                                startaddr + (firstzero - 1) - first_bit_offset);
            ret = -1;
            if (ret) {
                return ret;
            }
            */

            /* mask= .?0000000000 */
            /*         ^fz ^fs    */
            if (firstzero != 32) {
                mask &= (((uint32_t)-1) << firstzero);
            } else {
                mask = 0;
            }
        }
    }
    trace_loadvm_postcopy_ram_handle_discard_end();

    return 0;
}

/* After this message we must be able to immediately receive postcopy data */
static int loadvm_postcopy_handle_listen(MigrationIncomingState *mis)
{
    PostcopyState ps = postcopy_state_set(mis, POSTCOPY_INCOMING_LISTENING);
    trace_loadvm_postcopy_handle_listen();
    if (ps != POSTCOPY_INCOMING_ADVISE) {
        error_report("CMD_POSTCOPY_LISTEN in wrong postcopy state (%d)", ps);
        return -1;
    }

    /* TODO start up the postcopy listening thread */
    return 0;
}

/* After all discards we can start running and asking for pages */
static int loadvm_postcopy_handle_run(MigrationIncomingState *mis)
{
    PostcopyState ps = postcopy_state_set(mis, POSTCOPY_INCOMING_RUNNING);
    trace_loadvm_postcopy_handle_run();
    if (ps != POSTCOPY_INCOMING_LISTENING) {
        error_report("CMD_POSTCOPY_RUN in wrong postcopy state (%d)", ps);
        return -1;
    }

    if (autostart) {
        /* Hold onto your hats, starting the CPU */
        vm_start();
    } else {
        /* leave it paused and let management decide when to start the CPU */
        runstate_set(RUN_STATE_PAUSED);
    }

    return 0;
}

/* The end - with a byte from the source which can tell us to fail. */
static int loadvm_postcopy_handle_end(MigrationIncomingState *mis)
{
    PostcopyState ps = postcopy_state_get(mis);
    trace_loadvm_postcopy_handle_end();
    if (ps == POSTCOPY_INCOMING_NONE) {
        error_report("CMD_POSTCOPY_END in wrong postcopy state (%d)", ps);
        return -1;
    }
    return -1; /* TODO - expecting 1 byte good/fail */
}

static int loadvm_process_command_simple_lencheck(const char *name,
                                                  unsigned int actual,
                                                  unsigned int expected)
{
    if (actual != expected) {
        error_report("%s received with bad length - expecting %d, got %d",
                     name, expected, actual);
        return -1;
    }

    return 0;
}

/*
 * Process an incoming 'QEMU_VM_COMMAND'
 * negative return on error (will issue error message)
 * 0   just a normal return
 * 1   All good, but exit the loop
 */
static int loadvm_process_command(QEMUFile *f)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    uint16_t com;
    uint16_t len;
    uint32_t tmp32;
    uint64_t tmp64a, tmp64b;

    com = qemu_get_be16(f);
    len = qemu_get_be16(f);

    trace_loadvm_process_command(com, len);
    switch (com) {
    case MIG_CMD_OPEN_RETURN_PATH:
        if (loadvm_process_command_simple_lencheck("CMD_OPEN_RETURN_PATH",
                                                   len, 0)) {
            return -1;
        }
        if (mis->return_path) {
            error_report("CMD_OPEN_RETURN_PATH called when RP already open");
            /* Not really a problem, so don't give up */
            return 0;
        }
        mis->return_path = qemu_file_get_return_path(f);
        if (!mis->return_path) {
            error_report("CMD_OPEN_RETURN_PATH failed");
            return -1;
        }
        break;

    case MIG_CMD_PING:
        if (loadvm_process_command_simple_lencheck("CMD_PING", len, 4)) {
            return -1;
        }
        tmp32 = qemu_get_be32(f);
        trace_loadvm_process_command_ping(tmp32);
        if (!mis->return_path) {
            error_report("CMD_PING (0x%x) received with no return path",
                         tmp32);
            return -1;
        }
        migrate_send_rp_pong(mis, tmp32);
        break;

    case MIG_CMD_POSTCOPY_ADVISE:
        if (loadvm_process_command_simple_lencheck("CMD_POSTCOPY_ADVISE",
                                                   len, 16)) {
            return -1;
        }
        tmp64a = qemu_get_be64(f); /* hps */
        tmp64b = qemu_get_be64(f); /* tps */
        return loadvm_postcopy_handle_advise(mis, tmp64a, tmp64b);

    case MIG_CMD_POSTCOPY_LISTEN:
        if (loadvm_process_command_simple_lencheck("CMD_POSTCOPY_LISTEN",
                                                   len, 0)) {
            return -1;
        }
        return loadvm_postcopy_handle_listen(mis);

    case MIG_CMD_POSTCOPY_RUN:
        if (loadvm_process_command_simple_lencheck("CMD_POSTCOPY_RUN",
                                                   len, 0)) {
            return -1;
        }
        return loadvm_postcopy_handle_run(mis);

    case MIG_CMD_POSTCOPY_END:
        if (loadvm_process_command_simple_lencheck("CMD_POSTCOPY_END",
                                                   len, 1)) {
            return -1;
        }
        return loadvm_postcopy_handle_end(mis);

    case MIG_CMD_POSTCOPY_RAM_DISCARD:
        return loadvm_postcopy_ram_handle_discard(mis, len);

    default:
        error_report("VM_COMMAND 0x%x unknown (len 0x%x)", com, len);
        return -1;
    }

    return 0;
}

struct LoadStateEntry {
    QLIST_ENTRY(LoadStateEntry) entry;
    SaveStateEntry *se;
    int section_id;
    int version_id;
};

void loadvm_free_handlers(MigrationIncomingState *mis)
{
    LoadStateEntry *le, *new_le;

    QLIST_FOREACH_SAFE(le, &mis->loadvm_handlers, entry, new_le) {
        QLIST_REMOVE(le, entry);
        g_free(le);
    }
}

static int qemu_loadvm_state_main(QEMUFile *f, MigrationIncomingState *mis)
{
    uint8_t section_type;
    int ret;
    int exitcode = 0;

    trace_qemu_loadvm_state_main();
    while ((section_type = qemu_get_byte(f)) != QEMU_VM_EOF) {
        uint32_t instance_id, version_id, section_id;
        SaveStateEntry *se;
        LoadStateEntry *le;
        char idstr[256];

        trace_qemu_loadvm_state_section(section_type);
        switch (section_type) {
        case QEMU_VM_SECTION_START:
        case QEMU_VM_SECTION_FULL:
            /* Read section start */
            section_id = qemu_get_be32(f);
            if (qemu_get_counted_string(f, idstr)) {
                error_report("Unable to read ID string for section %u",
                            section_id);
                return -EINVAL;
            }
            instance_id = qemu_get_be32(f);
            version_id = qemu_get_be32(f);

            trace_qemu_loadvm_state_section_startfull(section_id, idstr,
                                                      instance_id, version_id);
            /* Find savevm section */
            se = find_se(idstr, instance_id);
            if (se == NULL) {
                error_report("Unknown savevm section or instance '%s' %d",
                             idstr, instance_id);
                return -EINVAL;
            }

            /* Validate version */
            if (version_id > se->version_id) {
                error_report("savevm: unsupported version %d for '%s' v%d",
                             version_id, idstr, se->version_id);
                return -EINVAL;
            }

            /* Add entry */
            le = g_malloc0(sizeof(*le));

            le->se = se;
            le->section_id = section_id;
            le->version_id = version_id;
            QLIST_INSERT_HEAD(&mis->loadvm_handlers, le, entry);

            ret = vmstate_load(f, le->se, le->version_id);
            if (ret < 0) {
                error_report("error while loading state for instance 0x%x of"
                             " device '%s'", instance_id, idstr);
                return ret;
            }
            break;
        case QEMU_VM_SECTION_PART:
        case QEMU_VM_SECTION_END:
            section_id = qemu_get_be32(f);

            trace_qemu_loadvm_state_section_partend(section_id);
            QLIST_FOREACH(le, &mis->loadvm_handlers, entry) {
                if (le->section_id == section_id) {
                    break;
                }
            }
            if (le == NULL) {
                error_report("Unknown savevm section %d", section_id);
                return -EINVAL;
            }

            ret = vmstate_load(f, le->se, le->version_id);
            if (ret < 0) {
                error_report("error while loading state section id %d(%s)",
                             section_id, le->se->idstr);
                return ret;
            }
            break;
        case QEMU_VM_COMMAND:
            ret = loadvm_process_command(f);
            trace_qemu_loadvm_state_section_command(ret);
            if ((ret < 0) || (ret & LOADVM_QUIT_LOOP)) {
                return ret;
            }
            exitcode |= ret; /* Lets us pass flags up to the parent */
            break;
        default:
            error_report("Unknown savevm section type %d", section_type);
            return -EINVAL;
        }
    }

    if (exitcode & LOADVM_QUIT_PARENT) {
        trace_qemu_loadvm_state_main_quit_parent();
        exitcode &= ~LOADVM_QUIT_PARENT;
        exitcode |= LOADVM_QUIT_LOOP;
    }

    return exitcode;
}

int qemu_loadvm_state(QEMUFile *f)
{
    MigrationIncomingState *mis = migration_incoming_get_current();
    Error *local_err = NULL;
    unsigned int v;
    int ret;

    if (qemu_savevm_state_blocked(&local_err)) {
        error_report("%s", error_get_pretty(local_err));
        error_free(local_err);
        return -EINVAL;
    }

    v = qemu_get_be32(f);
    if (v != QEMU_VM_FILE_MAGIC) {
        error_report("Not a migration stream");
        return -EINVAL;
    }

    v = qemu_get_be32(f);
    if (v == QEMU_VM_FILE_VERSION_COMPAT) {
        error_report("SaveVM v2 format is obsolete and don't work anymore");
        return -ENOTSUP;
    }
    if (v != QEMU_VM_FILE_VERSION) {
        error_report("Unsupported migration stream version");
        return -ENOTSUP;
    }

    ret = qemu_loadvm_state_main(f, mis);

    trace_qemu_loadvm_state_post_main(ret);
    if (ret == 0) {
        cpu_synchronize_all_post_init();
        ret = qemu_file_get_error(f);
    }

    return ret;
}

static BlockDriverState *find_vmstate_bs(void)
{
    BlockDriverState *bs = NULL;
    while ((bs = bdrv_next(bs))) {
        if (bdrv_can_snapshot(bs)) {
            return bs;
        }
    }
    return NULL;
}

/*
 * Deletes snapshots of a given name in all opened images.
 */
static int del_existing_snapshots(Monitor *mon, const char *name)
{
    BlockDriverState *bs;
    QEMUSnapshotInfo sn1, *snapshot = &sn1;
    Error *err = NULL;

    bs = NULL;
    while ((bs = bdrv_next(bs))) {
        if (bdrv_can_snapshot(bs) &&
            bdrv_snapshot_find(bs, snapshot, name) >= 0) {
            bdrv_snapshot_delete_by_id_or_name(bs, name, &err);
            if (err) {
                monitor_printf(mon,
                               "Error while deleting snapshot on device '%s':"
                               " %s\n",
                               bdrv_get_device_name(bs),
                               error_get_pretty(err));
                error_free(err);
                return -1;
            }
        }
    }

    return 0;
}

void do_savevm(Monitor *mon, const QDict *qdict)
{
    BlockDriverState *bs, *bs1;
    QEMUSnapshotInfo sn1, *sn = &sn1, old_sn1, *old_sn = &old_sn1;
    int ret;
    QEMUFile *f;
    int saved_vm_running;
    uint64_t vm_state_size;
    qemu_timeval tv;
    struct tm tm;
    const char *name = qdict_get_try_str(qdict, "name");

    /* Verify if there is a device that doesn't support snapshots and is writable */
    bs = NULL;
    while ((bs = bdrv_next(bs))) {

        if (!bdrv_is_inserted(bs) || bdrv_is_read_only(bs)) {
            continue;
        }

        if (!bdrv_can_snapshot(bs)) {
            monitor_printf(mon, "Device '%s' is writable but does not support snapshots.\n",
                               bdrv_get_device_name(bs));
            return;
        }
    }

    bs = find_vmstate_bs();
    if (!bs) {
        monitor_printf(mon, "No block device can accept snapshots\n");
        return;
    }

    saved_vm_running = runstate_is_running();
    vm_stop(RUN_STATE_SAVE_VM);

    memset(sn, 0, sizeof(*sn));

    /* fill auxiliary fields */
    qemu_gettimeofday(&tv);
    sn->date_sec = tv.tv_sec;
    sn->date_nsec = tv.tv_usec * 1000;
    sn->vm_clock_nsec = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    if (name) {
        ret = bdrv_snapshot_find(bs, old_sn, name);
        if (ret >= 0) {
            pstrcpy(sn->name, sizeof(sn->name), old_sn->name);
            pstrcpy(sn->id_str, sizeof(sn->id_str), old_sn->id_str);
        } else {
            pstrcpy(sn->name, sizeof(sn->name), name);
        }
    } else {
        /* cast below needed for OpenBSD where tv_sec is still 'long' */
        localtime_r((const time_t *)&tv.tv_sec, &tm);
        strftime(sn->name, sizeof(sn->name), "vm-%Y%m%d%H%M%S", &tm);
    }

    /* Delete old snapshots of the same name */
    if (name && del_existing_snapshots(mon, name) < 0) {
        goto the_end;
    }

    /* save the VM state */
    f = qemu_fopen_bdrv(bs, 1);
    if (!f) {
        monitor_printf(mon, "Could not open VM state file\n");
        goto the_end;
    }
    ret = qemu_savevm_state(f);
    vm_state_size = qemu_ftell(f);
    qemu_fclose(f);
    if (ret < 0) {
        monitor_printf(mon, "Error %d while writing VM\n", ret);
        goto the_end;
    }

    /* create the snapshots */

    bs1 = NULL;
    while ((bs1 = bdrv_next(bs1))) {
        if (bdrv_can_snapshot(bs1)) {
            /* Write VM state size only to the image that contains the state */
            sn->vm_state_size = (bs == bs1 ? vm_state_size : 0);
            ret = bdrv_snapshot_create(bs1, sn);
            if (ret < 0) {
                monitor_printf(mon, "Error while creating snapshot on '%s'\n",
                               bdrv_get_device_name(bs1));
            }
        }
    }

 the_end:
    if (saved_vm_running) {
        vm_start();
    }
}

void qmp_xen_save_devices_state(const char *filename, Error **errp)
{
    QEMUFile *f;
    int saved_vm_running;
    int ret;

    saved_vm_running = runstate_is_running();
    vm_stop(RUN_STATE_SAVE_VM);

    f = qemu_fopen(filename, "wb");
    if (!f) {
        error_setg_file_open(errp, errno, filename);
        goto the_end;
    }
    ret = qemu_save_device_state(f);
    qemu_fclose(f);
    if (ret < 0) {
        error_set(errp, QERR_IO_ERROR);
    }

 the_end:
    if (saved_vm_running) {
        vm_start();
    }
}

int load_vmstate(const char *name)
{
    BlockDriverState *bs, *bs_vm_state;
    QEMUSnapshotInfo sn;
    QEMUFile *f;
    int ret;

    bs_vm_state = find_vmstate_bs();
    if (!bs_vm_state) {
        error_report("No block device supports snapshots");
        return -ENOTSUP;
    }

    /* Don't even try to load empty VM states */
    ret = bdrv_snapshot_find(bs_vm_state, &sn, name);
    if (ret < 0) {
        return ret;
    } else if (sn.vm_state_size == 0) {
        error_report("This is a disk-only snapshot. Revert to it offline "
            "using qemu-img.");
        return -EINVAL;
    }

    /* Verify if there is any device that doesn't support snapshots and is
    writable and check if the requested snapshot is available too. */
    bs = NULL;
    while ((bs = bdrv_next(bs))) {

        if (!bdrv_is_inserted(bs) || bdrv_is_read_only(bs)) {
            continue;
        }

        if (!bdrv_can_snapshot(bs)) {
            error_report("Device '%s' is writable but does not support snapshots.",
                               bdrv_get_device_name(bs));
            return -ENOTSUP;
        }

        ret = bdrv_snapshot_find(bs, &sn, name);
        if (ret < 0) {
            error_report("Device '%s' does not have the requested snapshot '%s'",
                           bdrv_get_device_name(bs), name);
            return ret;
        }
    }

    /* Flush all IO requests so they don't interfere with the new state.  */
    bdrv_drain_all();

    bs = NULL;
    while ((bs = bdrv_next(bs))) {
        if (bdrv_can_snapshot(bs)) {
            ret = bdrv_snapshot_goto(bs, name);
            if (ret < 0) {
                error_report("Error %d while activating snapshot '%s' on '%s'",
                             ret, name, bdrv_get_device_name(bs));
                return ret;
            }
        }
    }

    /* restore the VM state */
    f = qemu_fopen_bdrv(bs_vm_state, 0);
    if (!f) {
        error_report("Could not open VM state file");
        return -EINVAL;
    }

    qemu_system_reset(VMRESET_SILENT);
    migration_incoming_state_new(f);
    ret = qemu_loadvm_state(f);

    qemu_fclose(f);
    migration_incoming_state_destroy();
    if (ret < 0) {
        error_report("Error %d while loading VM state", ret);
        return ret;
    }

    return 0;
}

void do_delvm(Monitor *mon, const QDict *qdict)
{
    BlockDriverState *bs;
    Error *err;
    const char *name = qdict_get_str(qdict, "name");

    if (!find_vmstate_bs()) {
        monitor_printf(mon, "No block device supports snapshots\n");
        return;
    }

    bs = NULL;
    while ((bs = bdrv_next(bs))) {
        if (bdrv_can_snapshot(bs)) {
            err = NULL;
            bdrv_snapshot_delete_by_id_or_name(bs, name, &err);
            if (err) {
                monitor_printf(mon,
                               "Error while deleting snapshot on device '%s':"
                               " %s\n",
                               bdrv_get_device_name(bs),
                               error_get_pretty(err));
                error_free(err);
            }
        }
    }
}

void do_info_snapshots(Monitor *mon, const QDict *qdict)
{
    BlockDriverState *bs, *bs1;
    QEMUSnapshotInfo *sn_tab, *sn, s, *sn_info = &s;
    int nb_sns, i, ret, available;
    int total;
    int *available_snapshots;

    bs = find_vmstate_bs();
    if (!bs) {
        monitor_printf(mon, "No available block device supports snapshots\n");
        return;
    }

    nb_sns = bdrv_snapshot_list(bs, &sn_tab);
    if (nb_sns < 0) {
        monitor_printf(mon, "bdrv_snapshot_list: error %d\n", nb_sns);
        return;
    }

    if (nb_sns == 0) {
        monitor_printf(mon, "There is no snapshot available.\n");
        return;
    }

    available_snapshots = g_malloc0(sizeof(int) * nb_sns);
    total = 0;
    for (i = 0; i < nb_sns; i++) {
        sn = &sn_tab[i];
        available = 1;
        bs1 = NULL;

        while ((bs1 = bdrv_next(bs1))) {
            if (bdrv_can_snapshot(bs1) && bs1 != bs) {
                ret = bdrv_snapshot_find(bs1, sn_info, sn->id_str);
                if (ret < 0) {
                    available = 0;
                    break;
                }
            }
        }

        if (available) {
            available_snapshots[total] = i;
            total++;
        }
    }

    if (total > 0) {
        bdrv_snapshot_dump((fprintf_function)monitor_printf, mon, NULL);
        monitor_printf(mon, "\n");
        for (i = 0; i < total; i++) {
            sn = &sn_tab[available_snapshots[i]];
            bdrv_snapshot_dump((fprintf_function)monitor_printf, mon, sn);
            monitor_printf(mon, "\n");
        }
    } else {
        monitor_printf(mon, "There is no suitable snapshot available\n");
    }

    g_free(sn_tab);
    g_free(available_snapshots);

}

void vmstate_register_ram(MemoryRegion *mr, DeviceState *dev)
{
    qemu_ram_set_idstr(memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK,
                       memory_region_name(mr), dev);
}

void vmstate_unregister_ram(MemoryRegion *mr, DeviceState *dev)
{
    qemu_ram_unset_idstr(memory_region_get_ram_addr(mr) & TARGET_PAGE_MASK);
}

void vmstate_register_ram_global(MemoryRegion *mr)
{
    vmstate_register_ram(mr, NULL);
}
