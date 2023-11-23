/*
 * RISC-V specific prctl functions for linux-user
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RISCV_TARGET_PRCTL_H
#define RISCV_TARGET_PRCTL_H

static inline void riscv_dtso_set_enable(CPURISCVState *env, bool enable)
{
    env->dtso_ena = enable;
}

static inline bool riscv_dtso_is_enabled(CPURISCVState *env)
{
    return env->dtso_ena;
}

static abi_long do_prctl_set_memory_consistency_model(CPUArchState *cpu_env,
                                                      abi_long arg2)
{
    RISCVCPU *cpu = env_archcpu(cpu_env);
    bool dtso_ena_old = riscv_dtso_is_enabled(cpu_env);
    bool dtso_ena_new;
    bool has_dtso = cpu->cfg.ext_ssdtso;

    switch (arg2) {
        case PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO:
            dtso_ena_new = false;
            break;
        case PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO:
	    dtso_ena_new = true;
            break;
        default:
            return -TARGET_EINVAL;
    }

    /* No change requested. */
    if (dtso_ena_old == dtso_ena_new)
	    return 0;

    /* Enabling TSO only works if DTSO is available. */
    if (dtso_ena_new && !has_dtso)
	    return -TARGET_EINVAL;

    /* Switchin TSO->WMO is not allowed. */
    if (!dtso_ena_new)
	    return -TARGET_EINVAL;

    riscv_dtso_set_enable(cpu_env, dtso_ena_new);

    /*
     * No need to reschedule other threads, because the emulation
     * of DTSO is fine (from a memory model view) if they are out
     * of sync until they will eventually reschedule.
     */

    return 0;
}

#define do_prctl_set_memory_consistency_model \
        do_prctl_set_memory_consistency_model

static abi_long do_prctl_get_memory_consistency_model(CPUArchState *cpu_env)
{
    if (riscv_dtso_is_enabled(cpu_env))
	    return PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO;

    return PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO;
}

#define do_prctl_get_memory_consistency_model \
        do_prctl_get_memory_consistency_model

#endif /* RISCV_TARGET_PRCTL_H */
