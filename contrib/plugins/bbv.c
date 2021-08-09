/*
 * Basic-block Vector (BBV) Collection Plugin
 *
 * Simpointing tools read a BBV (basic-block vector) file summarizing
 * the frequency of individual basic blocks being executed per
 * instruction-slice.  This plugin instruments a binary executed in
 * qemu and writes a basic-block vector file on completion.
 *
 * Copyright (C) 2021, VRULL GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

static GHashTable *blocks;
uint64_t insns_interval_length = 100000000;
FILE *bb_out = NULL;
FILE *pc_out = NULL;

/* We measure the  */
static uint64_t  insns_executed = 0;
static uint64_t next_tbid = 0;
struct BBExecutionFrequency {
    uint64_t    tbid;
    uint64_t    tb_pc;
    uint64_t    n_insns;
    uint64_t    tb_dynamic_count;
    const char *symbol;
    uint64_t    offset_from_symbol;
};

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void plugin_init(void)
{
    blocks = g_hash_table_new(NULL, g_direct_equal);
}

static gint cmp_tbid(gconstpointer a, gconstpointer b)
{
    struct BBExecutionFrequency *info_a = (struct BBExecutionFrequency *)a;
    struct BBExecutionFrequency *info_b = (struct BBExecutionFrequency *)b;

    return info_a->tbid - info_b->tbid;
}

static void print_bb_freq (gpointer key, gpointer data, gpointer user_data)
{
    struct BBExecutionFrequency *info = (struct BBExecutionFrequency *)data;
    if (info->tb_dynamic_count) {
        fprintf(bb_out, ":%ld:%ld ", info->tbid, info->tb_dynamic_count);
        info->tb_dynamic_count = 0;
    }
}

static void handle_interval_expiry(void)
{
    if (!bb_out)
        return;

    fprintf(bb_out, "T");
    g_hash_table_foreach(blocks, print_bb_freq, NULL);
    fprintf(bb_out, "\n");
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    GList *blocks_values, *it;
    g_autoptr(GString) report = g_string_new("");

    handle_interval_expiry();
    blocks_values = g_hash_table_get_values(blocks);

    if (pc_out) {
        it = g_list_sort(blocks_values, cmp_tbid);

        for (GList *e = it; e->next; e = e->next) {
            struct BBExecutionFrequency *info = (struct BBExecutionFrequency *)e->data;
            fprintf(pc_out, "F:%ld:%lx:%s\n", info->tbid, info->tb_pc,
                    info->symbol ? info->symbol : "");
        }
        g_list_free(it);
    }

    if (bb_out)
        fclose(bb_out);

    if (pc_out)
        fclose(pc_out);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    struct BBExecutionFrequency *info = (struct BBExecutionFrequency *)udata;
    insns_executed += info->n_insns;
    info->tb_dynamic_count += info->n_insns;
    if (insns_executed > insns_interval_length) {
        insns_executed -= insns_interval_length;
        info->tb_dynamic_count -= insns_executed;
        handle_interval_expiry();
        info->tb_dynamic_count = insns_executed;
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct BBExecutionFrequency *info;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    info = (struct BBExecutionFrequency *) g_hash_table_lookup(blocks, (gconstpointer) pc);
    if (!info) {
        info = g_new0(struct BBExecutionFrequency, 1);
        info->tbid = next_tbid++;
        info->tb_pc = pc;
        info->tb_dynamic_count = 0;
        info->n_insns = n_insns;
        info->symbol = qemu_plugin_insn_symbol(qemu_plugin_tb_get_insn(tb, 0));
        g_hash_table_insert(blocks, (gpointer) pc, (gpointer) info);
    }

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)info);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;
    char* bb_out_file_name = NULL;
    char* pc_out_file_name = NULL;

    for (i = 0; i < argc; i++) {
        char *opt = argv[i];

        if (g_str_has_prefix(opt, "bb-out-file="))
            bb_out_file_name = opt + 12;
        else if (g_str_has_prefix(opt, "pc-out-file="))
            pc_out_file_name = opt + 12;
        else if (g_str_has_prefix(opt, "interval-size="))
            insns_interval_length = g_ascii_strtoull(opt + 14, NULL, 10);
        else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (bb_out_file_name)
        bb_out = fopen(bb_out_file_name, "w");

    if (pc_out_file_name)
        pc_out = fopen(pc_out_file_name, "w");


    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
