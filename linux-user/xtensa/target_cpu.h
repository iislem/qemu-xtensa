/*
 * Xtensa-specific CPU ABI and functions for linux-user
 */
#ifndef XTENSA_TARGET_CPU_H
#define XTENSA_TARGET_CPU_H

static inline void cpu_clone_regs(CPUXtensaState *env, target_ulong newsp)
{
    if (newsp) {
        env->regs[1] = newsp;
    }
    env->regs[0] = 0;
}

static inline void cpu_set_tls(CPUXtensaState *env, target_ulong newtls)
{
    env->uregs[THREADPTR] = newtls;
}

#endif
