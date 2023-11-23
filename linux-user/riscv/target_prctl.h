/*
 * RISC-V specific prctl functions for linux-user
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RISCV_TARGET_PRCTL_H
#define RISCV_TARGET_PRCTL_H

static inline void riscv_dtso_enable(CPURISCVState *env)
{
    env->dtso_ena = true;
}

static inline void riscv_dtso_disable(CPURISCVState *env)
{
    env->dtso_ena = false;
}

static inline bool riscv_dtso_is_enabled(CPURISCVState *env)
{
    return env->dtso_ena;
}

static abi_long do_prctl_set_memory_consistency_model(CPUArchState *cpu_env,
                                                      abi_long arg2)
{
    RISCVCPU *cpu = env_archcpu(cpu_env);
    bool has_dtso = cpu->cfg.ext_ssdtso;

    switch (arg2) {
        case PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO:
            if (has_dtso)
                riscv_dtso_disable(cpu_env);
            break;
        case PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO:
            if (has_dtso)
                riscv_dtso_enable(cpu_env);
            break;
        default:
            return -TARGET_EINVAL;
    }

    return 0;
}

#define do_prctl_set_memory_consistency_model \
	do_prctl_set_memory_consistency_model

static abi_long do_prctl_get_memory_consistency_model(CPUArchState *cpu_env)
{
    RISCVCPU *cpu = env_archcpu(cpu_env);
    bool has_tso = cpu->cfg.ext_ztso;
    bool has_dtso = cpu->cfg.ext_ssdtso;

    if (has_dtso && riscv_dtso_is_enabled(cpu_env))
        return PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO;
    return has_tso ? PR_MEMORY_CONSISTENCY_MODEL_RISCV_TSO :
           PR_MEMORY_CONSISTENCY_MODEL_RISCV_WMO;
}

#define do_prctl_get_memory_consistency_model \
	do_prctl_get_memory_consistency_model

#endif /* RISCV_TARGET_PRCTL_H */
