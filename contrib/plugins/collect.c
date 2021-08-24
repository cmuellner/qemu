/*
 * Copyright (C) 2021, Philipp Tomsich <philipp.tomsich@vrull.eu>
 *
 * Collect data on all translated and executed blocks to support out-of-band
 * analysis for the following use-cases:
 *  - hot-block analysis
 *    + by invocation count
 *    + by executed instructions
 *  - hot-functions
 *    + by invocation count
 *    + by executed instructions
 *  - instruction histograms
 *  - dynamic instruction count
 *
 * License: GNU GPL, version 2 or later.
 *          See the COPYRIGHT file in the top-level directory.
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

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Plugins need to take care of their own locking */
static GMutex lock;
static GHashTable *blocks;

/*
 * Counting Structure
 *
 * The internals of the TCG are not exposed to plugins so we can only
 * get the starting PC for each block. We cheat this slightly by
 * xor'ing the number of instructions to the hash to help
 * differentiate.
 */
struct qemu_insn {
    size_t   len;
    uint64_t data;
    const char* disasm;
};

typedef struct TBExecCount {
    uint64_t     start_addr;
    uint64_t     exec_count;
    uint64_t     trans_count;
    uint64_t     n_insns;
    struct qemu_insn  *insns;
    const char  *symbol;
    struct TBExecCount *next;
} TBExecCount;

static gint cmp_dynamic_insncount(gconstpointer a, gconstpointer b)
{
    TBExecCount *ea = (TBExecCount *) a;
    TBExecCount *eb = (TBExecCount *) b;
    return (ea->exec_count * ea->n_insns) > (eb->exec_count * eb->n_insns) ? -1 : 1;
}

static gint cmp_dynamic_execcount(gconstpointer a, gconstpointer b)
{
    TBExecCount *ea = (TBExecCount *) a;
    TBExecCount *eb = (TBExecCount *) b;
    return (ea->exec_count) > (eb->exec_count) ? -1 : 1;
}

/*
 *
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    /* code may be self-modifying */
    /* 1. lookup if the start_addr is already known */
    /* 2. compare if the num_insn is the same */
    /* 3. create a new block, if insns have changed */
    
    TBExecCount *cnt;
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t insns = qemu_plugin_tb_n_insns(tb);
    uint64_t hash = pc /* ^ insns */;

    g_mutex_lock(&lock);
    cnt = (TBExecCount *) g_hash_table_lookup(blocks, (gconstpointer) hash);
    if (cnt) {
        cnt->trans_count++;

        /* TODO: handle adding a new cnt and new insns */
    } else {
        cnt = g_new0(TBExecCount, 1);
        cnt->start_addr = pc;
        cnt->trans_count = 1;
        cnt->n_insns = insns;
        cnt->next = NULL;
        cnt->insns = malloc(sizeof(struct qemu_insn) * insns);
        cnt->symbol = qemu_plugin_insn_symbol(qemu_plugin_tb_get_insn(tb, 0));
        
        for (int i = 0; i < insns; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            cnt->insns[i].len = qemu_plugin_insn_size(insn);
            switch(cnt->insns[i].len) {
            case 4:
                cnt->insns[i].data = *(uint32_t *)qemu_plugin_insn_data(insn);
                break;
            case 2:
                cnt->insns[i].data = *(uint16_t *)qemu_plugin_insn_data(insn);
                break;
            }
            cnt->insns[i].disasm = qemu_plugin_insn_disas(insn);
        }
        
        g_hash_table_insert(blocks, (gpointer) hash, (gpointer) cnt);
        /* TODO: count per symbols */
    }

    g_mutex_unlock(&lock);

    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cnt->exec_count, 1);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    /*
     * Create a dump file and a summary file.
     * The summary contains:
     *   Dynamic instruction count
     *   50 hottest blocks by number of instructions executed
     *   statistics on the plugin
     */
    g_autoptr(GString) report = g_string_new("collected ");
    GList *counts, *it;
    int i;

    g_mutex_lock(&lock);
    g_string_append_printf(report, "%d translation blocks\n",
                           g_hash_table_size(blocks));
    counts = g_hash_table_get_values(blocks);

    g_string_append_printf(report, "## Blocks (by dynamic instructions)\n\n");
    /* Hot-blocks, by executed instructions */
    it = g_list_sort(counts, cmp_dynamic_insncount);

    uint64_t total_insn_executed = 0;

    if (it) {
        for (GList *e = it; e->next;  e = e->next) {
            TBExecCount *rec = (TBExecCount *) e->data;
            total_insn_executed += rec->n_insns * rec->exec_count;
        }

        for (GList *e = it; e->next; e = e->next) {
            TBExecCount *rec = (TBExecCount *) e->data;
            uint64_t n_insn_executed = rec->n_insns * rec->exec_count;
            g_string_append_printf(report, "  0x%016"PRIx64" %"PRId64" %.4lf%% %s\n",
                                   rec->start_addr,
                                   n_insn_executed,
                                   ((double)n_insn_executed * 100)/total_insn_executed,
                                   rec->symbol ? rec->symbol : "");

            for (i = 0; i < rec->n_insns; ++i) {
                g_string_append_printf(report, "      %s\n",
                                       rec->insns[i].disasm);

            }
        }

        g_list_free(it);
    }

    g_string_append_printf(report, "\n## Blocks (by dynamic invocations)\n\n");

    /* Hot-blocks, by block executions */
    counts = g_hash_table_get_values(blocks);
    it = g_list_sort(counts, cmp_dynamic_execcount);
    if (it) {
        for (GList *e = it; e->next; e = e->next) {
            TBExecCount *rec = (TBExecCount *) e->data;
            uint64_t n_insn_executed = rec->exec_count;
            g_string_append_printf(report, "  0x%016"PRIx64" %"PRId64" %.4lf%% %s\n",
                                   rec->start_addr,
                                   rec->exec_count,
                                   ((double)n_insn_executed * 100)/total_insn_executed,
                                   rec->symbol ? rec->symbol : "");
        }

        g_list_free(it);
    }

    g_string_append_printf(report, "\n## Summary\n\n");
    g_string_append_printf(report, "  Dynamic instruction count:   %"PRId64"\n",
                           total_insn_executed);
    g_string_append_printf(report, "  Translation blocks executed: %d\n",
                           g_hash_table_size(blocks));
    
    g_mutex_unlock(&lock);
    qemu_plugin_outs(report->str);
}

static void plugin_init(void)
{
    blocks = g_hash_table_new(NULL, g_direct_equal);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    /*
      - output file
      - ???

    if (argc && strcmp(argv[0], "inline") == 0) {
        do_inline = true;
    }
    */

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}

