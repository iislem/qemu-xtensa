/*
 * Xtensa ISA:
 * http://www.tensilica.com/products/literature-docs/documentation/xtensa-isa-databook.htm
 *
 * Copyright (c) 2011, Max Filippov, Open Source and Linux Lab.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Open Source and Linux Lab nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "qemu/osdep.h"

#include "cpu.h"
#include "exec/exec-all.h"
#include "disas/disas.h"
#include "tcg-op.h"
#include "qemu/log.h"
#include "sysemu/sysemu.h"
#include "exec/cpu_ldst.h"
#include "exec/semihost.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "trace-tcg.h"
#include "exec/log.h"


typedef struct DisasContext {
    const XtensaConfig *config;
    TranslationBlock *tb;
    uint32_t pc;
    uint32_t next_pc;
    int cring;
    int ring;
    uint32_t lbeg;
    uint32_t lend;
    TCGv_i32 litbase;
    int is_jmp;
    int singlestep_enabled;

    bool sar_5bit;
    bool sar_m32_5bit;
    bool sar_m32_allocated;
    TCGv_i32 sar_m32;

    unsigned window;

    bool debug;
    bool icount;
    TCGv_i32 next_icount;

    unsigned cpenable;

    uint32_t *raw_arg;
    xtensa_insnbuf insnbuf;
    xtensa_insnbuf slotbuf;
} DisasContext;

static TCGv_env cpu_env;
static TCGv_i32 cpu_pc;
static TCGv_i32 cpu_R[16];
static TCGv_i32 cpu_FR[16];
static TCGv_i32 cpu_SR[256];
static TCGv_i32 cpu_UR[256];

#include "exec/gen-icount.h"

typedef struct XtensaReg {
    const char *name;
    uint64_t opt_bits;
    enum {
        SR_R = 1,
        SR_W = 2,
        SR_X = 4,
        SR_RW = 3,
        SR_RWX = 7,
    } access;
} XtensaReg;

#define XTENSA_REG_ACCESS(regname, opt, acc) { \
        .name = (regname), \
        .opt_bits = XTENSA_OPTION_BIT(opt), \
        .access = (acc), \
    }

#define XTENSA_REG(regname, opt) XTENSA_REG_ACCESS(regname, opt, SR_RWX)

#define XTENSA_REG_BITS_ACCESS(regname, opt, acc) { \
        .name = (regname), \
        .opt_bits = (opt), \
        .access = (acc), \
    }

#define XTENSA_REG_BITS(regname, opt) \
    XTENSA_REG_BITS_ACCESS(regname, opt, SR_RWX)

static const XtensaReg sregnames[256] = {
    [LBEG] = XTENSA_REG("LBEG", XTENSA_OPTION_LOOP),
    [LEND] = XTENSA_REG("LEND", XTENSA_OPTION_LOOP),
    [LCOUNT] = XTENSA_REG("LCOUNT", XTENSA_OPTION_LOOP),
    [SAR] = XTENSA_REG_BITS("SAR", XTENSA_OPTION_ALL),
    [BR] = XTENSA_REG("BR", XTENSA_OPTION_BOOLEAN),
    [LITBASE] = XTENSA_REG("LITBASE", XTENSA_OPTION_EXTENDED_L32R),
    [SCOMPARE1] = XTENSA_REG("SCOMPARE1", XTENSA_OPTION_CONDITIONAL_STORE),
    [ACCLO] = XTENSA_REG("ACCLO", XTENSA_OPTION_MAC16),
    [ACCHI] = XTENSA_REG("ACCHI", XTENSA_OPTION_MAC16),
    [MR] = XTENSA_REG("MR0", XTENSA_OPTION_MAC16),
    [MR + 1] = XTENSA_REG("MR1", XTENSA_OPTION_MAC16),
    [MR + 2] = XTENSA_REG("MR2", XTENSA_OPTION_MAC16),
    [MR + 3] = XTENSA_REG("MR3", XTENSA_OPTION_MAC16),
    [WINDOW_BASE] = XTENSA_REG("WINDOW_BASE", XTENSA_OPTION_WINDOWED_REGISTER),
    [WINDOW_START] = XTENSA_REG("WINDOW_START",
            XTENSA_OPTION_WINDOWED_REGISTER),
    [PTEVADDR] = XTENSA_REG("PTEVADDR", XTENSA_OPTION_MMU),
    [RASID] = XTENSA_REG("RASID", XTENSA_OPTION_MMU),
    [ITLBCFG] = XTENSA_REG("ITLBCFG", XTENSA_OPTION_MMU),
    [DTLBCFG] = XTENSA_REG("DTLBCFG", XTENSA_OPTION_MMU),
    [IBREAKENABLE] = XTENSA_REG("IBREAKENABLE", XTENSA_OPTION_DEBUG),
    [MEMCTL] = XTENSA_REG_BITS("MEMCTL", XTENSA_OPTION_ALL),
    [CACHEATTR] = XTENSA_REG("CACHEATTR", XTENSA_OPTION_CACHEATTR),
    [ATOMCTL] = XTENSA_REG("ATOMCTL", XTENSA_OPTION_ATOMCTL),
    [IBREAKA] = XTENSA_REG("IBREAKA0", XTENSA_OPTION_DEBUG),
    [IBREAKA + 1] = XTENSA_REG("IBREAKA1", XTENSA_OPTION_DEBUG),
    [DBREAKA] = XTENSA_REG("DBREAKA0", XTENSA_OPTION_DEBUG),
    [DBREAKA + 1] = XTENSA_REG("DBREAKA1", XTENSA_OPTION_DEBUG),
    [DBREAKC] = XTENSA_REG("DBREAKC0", XTENSA_OPTION_DEBUG),
    [DBREAKC + 1] = XTENSA_REG("DBREAKC1", XTENSA_OPTION_DEBUG),
    [CONFIGID0] = XTENSA_REG_BITS_ACCESS("CONFIGID0", XTENSA_OPTION_ALL, SR_R),
    [EPC1] = XTENSA_REG("EPC1", XTENSA_OPTION_EXCEPTION),
    [EPC1 + 1] = XTENSA_REG("EPC2", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPC1 + 2] = XTENSA_REG("EPC3", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPC1 + 3] = XTENSA_REG("EPC4", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPC1 + 4] = XTENSA_REG("EPC5", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPC1 + 5] = XTENSA_REG("EPC6", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPC1 + 6] = XTENSA_REG("EPC7", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [DEPC] = XTENSA_REG("DEPC", XTENSA_OPTION_EXCEPTION),
    [EPS2] = XTENSA_REG("EPS2", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPS2 + 1] = XTENSA_REG("EPS3", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPS2 + 2] = XTENSA_REG("EPS4", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPS2 + 3] = XTENSA_REG("EPS5", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPS2 + 4] = XTENSA_REG("EPS6", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EPS2 + 5] = XTENSA_REG("EPS7", XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [CONFIGID1] = XTENSA_REG_BITS_ACCESS("CONFIGID1", XTENSA_OPTION_ALL, SR_R),
    [EXCSAVE1] = XTENSA_REG("EXCSAVE1", XTENSA_OPTION_EXCEPTION),
    [EXCSAVE1 + 1] = XTENSA_REG("EXCSAVE2",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EXCSAVE1 + 2] = XTENSA_REG("EXCSAVE3",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EXCSAVE1 + 3] = XTENSA_REG("EXCSAVE4",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EXCSAVE1 + 4] = XTENSA_REG("EXCSAVE5",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EXCSAVE1 + 5] = XTENSA_REG("EXCSAVE6",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [EXCSAVE1 + 6] = XTENSA_REG("EXCSAVE7",
            XTENSA_OPTION_HIGH_PRIORITY_INTERRUPT),
    [CPENABLE] = XTENSA_REG("CPENABLE", XTENSA_OPTION_COPROCESSOR),
    [INTSET] = XTENSA_REG_ACCESS("INTSET", XTENSA_OPTION_INTERRUPT, SR_RW),
    [INTCLEAR] = XTENSA_REG_ACCESS("INTCLEAR", XTENSA_OPTION_INTERRUPT, SR_W),
    [INTENABLE] = XTENSA_REG("INTENABLE", XTENSA_OPTION_INTERRUPT),
    [PS] = XTENSA_REG_BITS("PS", XTENSA_OPTION_ALL),
    [VECBASE] = XTENSA_REG("VECBASE", XTENSA_OPTION_RELOCATABLE_VECTOR),
    [EXCCAUSE] = XTENSA_REG("EXCCAUSE", XTENSA_OPTION_EXCEPTION),
    [DEBUGCAUSE] = XTENSA_REG_ACCESS("DEBUGCAUSE", XTENSA_OPTION_DEBUG, SR_R),
    [CCOUNT] = XTENSA_REG("CCOUNT", XTENSA_OPTION_TIMER_INTERRUPT),
    [PRID] = XTENSA_REG_ACCESS("PRID", XTENSA_OPTION_PROCESSOR_ID, SR_R),
    [ICOUNT] = XTENSA_REG("ICOUNT", XTENSA_OPTION_DEBUG),
    [ICOUNTLEVEL] = XTENSA_REG("ICOUNTLEVEL", XTENSA_OPTION_DEBUG),
    [EXCVADDR] = XTENSA_REG("EXCVADDR", XTENSA_OPTION_EXCEPTION),
    [CCOMPARE] = XTENSA_REG("CCOMPARE0", XTENSA_OPTION_TIMER_INTERRUPT),
    [CCOMPARE + 1] = XTENSA_REG("CCOMPARE1",
            XTENSA_OPTION_TIMER_INTERRUPT),
    [CCOMPARE + 2] = XTENSA_REG("CCOMPARE2",
            XTENSA_OPTION_TIMER_INTERRUPT),
    [MISC] = XTENSA_REG("MISC0", XTENSA_OPTION_MISC_SR),
    [MISC + 1] = XTENSA_REG("MISC1", XTENSA_OPTION_MISC_SR),
    [MISC + 2] = XTENSA_REG("MISC2", XTENSA_OPTION_MISC_SR),
    [MISC + 3] = XTENSA_REG("MISC3", XTENSA_OPTION_MISC_SR),
};

static const XtensaReg uregnames[256] = {
    [THREADPTR] = XTENSA_REG("THREADPTR", XTENSA_OPTION_THREAD_POINTER),
    [FCR] = XTENSA_REG("FCR", XTENSA_OPTION_FP_COPROCESSOR),
    [FSR] = XTENSA_REG("FSR", XTENSA_OPTION_FP_COPROCESSOR),
};

void xtensa_translate_init(void)
{
    static const char * const regnames[] = {
        "ar0", "ar1", "ar2", "ar3",
        "ar4", "ar5", "ar6", "ar7",
        "ar8", "ar9", "ar10", "ar11",
        "ar12", "ar13", "ar14", "ar15",
    };
    static const char * const fregnames[] = {
        "f0", "f1", "f2", "f3",
        "f4", "f5", "f6", "f7",
        "f8", "f9", "f10", "f11",
        "f12", "f13", "f14", "f15",
    };
    int i;

    cpu_env = tcg_global_reg_new_ptr(TCG_AREG0, "env");
    tcg_ctx.tcg_env = cpu_env;
    cpu_pc = tcg_global_mem_new_i32(cpu_env,
            offsetof(CPUXtensaState, pc), "pc");

    for (i = 0; i < 16; i++) {
        cpu_R[i] = tcg_global_mem_new_i32(cpu_env,
                offsetof(CPUXtensaState, regs[i]),
                regnames[i]);
    }

    for (i = 0; i < 16; i++) {
        cpu_FR[i] = tcg_global_mem_new_i32(cpu_env,
                offsetof(CPUXtensaState, fregs[i].f32[FP_F32_LOW]),
                fregnames[i]);
    }

    for (i = 0; i < 256; ++i) {
        if (sregnames[i].name) {
            cpu_SR[i] = tcg_global_mem_new_i32(cpu_env,
                    offsetof(CPUXtensaState, sregs[i]),
                    sregnames[i].name);
        }
    }

    for (i = 0; i < 256; ++i) {
        if (uregnames[i].name) {
            cpu_UR[i] = tcg_global_mem_new_i32(cpu_env,
                    offsetof(CPUXtensaState, uregs[i]),
                    uregnames[i].name);
        }
    }
}

static inline bool option_bits_enabled(DisasContext *dc, uint64_t opt)
{
    return xtensa_option_bits_enabled(dc->config, opt);
}

static inline bool option_enabled(DisasContext *dc, int opt)
{
    return xtensa_option_enabled(dc->config, opt);
}

static void init_litbase(DisasContext *dc)
{
    if (dc->tb->flags & XTENSA_TBFLAG_LITBASE) {
        dc->litbase = tcg_temp_local_new_i32();
        tcg_gen_andi_i32(dc->litbase, cpu_SR[LITBASE], 0xfffff000);
    }
}

static void reset_litbase(DisasContext *dc)
{
    if (dc->tb->flags & XTENSA_TBFLAG_LITBASE) {
        tcg_temp_free(dc->litbase);
    }
}

static void init_sar_tracker(DisasContext *dc)
{
    dc->sar_5bit = false;
    dc->sar_m32_5bit = false;
    dc->sar_m32_allocated = false;
}

static void reset_sar_tracker(DisasContext *dc)
{
    if (dc->sar_m32_allocated) {
        tcg_temp_free(dc->sar_m32);
    }
}

static void gen_right_shift_sar(DisasContext *dc, TCGv_i32 sa)
{
    tcg_gen_andi_i32(cpu_SR[SAR], sa, 0x1f);
    if (dc->sar_m32_5bit) {
        tcg_gen_discard_i32(dc->sar_m32);
    }
    dc->sar_5bit = true;
    dc->sar_m32_5bit = false;
}

static void gen_left_shift_sar(DisasContext *dc, TCGv_i32 sa)
{
    TCGv_i32 tmp = tcg_const_i32(32);
    if (!dc->sar_m32_allocated) {
        dc->sar_m32 = tcg_temp_local_new_i32();
        dc->sar_m32_allocated = true;
    }
    tcg_gen_andi_i32(dc->sar_m32, sa, 0x1f);
    tcg_gen_sub_i32(cpu_SR[SAR], tmp, dc->sar_m32);
    dc->sar_5bit = false;
    dc->sar_m32_5bit = true;
    tcg_temp_free(tmp);
}

static void gen_exception(DisasContext *dc, int excp)
{
    TCGv_i32 tmp = tcg_const_i32(excp);
    gen_helper_exception(cpu_env, tmp);
    tcg_temp_free(tmp);
}

static void gen_exception_cause(DisasContext *dc, uint32_t cause)
{
    TCGv_i32 tpc = tcg_const_i32(dc->pc);
    TCGv_i32 tcause = tcg_const_i32(cause);
    gen_helper_exception_cause(cpu_env, tpc, tcause);
    tcg_temp_free(tpc);
    tcg_temp_free(tcause);
    if (cause == ILLEGAL_INSTRUCTION_CAUSE ||
            cause == SYSCALL_CAUSE) {
        dc->is_jmp = DISAS_UPDATE;
    }
}

static void gen_exception_cause_vaddr(DisasContext *dc, uint32_t cause,
        TCGv_i32 vaddr)
{
    TCGv_i32 tpc = tcg_const_i32(dc->pc);
    TCGv_i32 tcause = tcg_const_i32(cause);
    gen_helper_exception_cause_vaddr(cpu_env, tpc, tcause, vaddr);
    tcg_temp_free(tpc);
    tcg_temp_free(tcause);
}

static void gen_debug_exception(DisasContext *dc, uint32_t cause)
{
    TCGv_i32 tpc = tcg_const_i32(dc->pc);
    TCGv_i32 tcause = tcg_const_i32(cause);
    gen_helper_debug_exception(cpu_env, tpc, tcause);
    tcg_temp_free(tpc);
    tcg_temp_free(tcause);
    if (cause & (DEBUGCAUSE_IB | DEBUGCAUSE_BI | DEBUGCAUSE_BN)) {
        dc->is_jmp = DISAS_UPDATE;
    }
}

static bool gen_check_privilege(DisasContext *dc)
{
    if (dc->cring) {
        gen_exception_cause(dc, PRIVILEGED_CAUSE);
        dc->is_jmp = DISAS_UPDATE;
        return false;
    }
    return true;
}

static bool gen_check_cpenable(DisasContext *dc, unsigned cp)
{
    if (option_enabled(dc, XTENSA_OPTION_COPROCESSOR) &&
            !(dc->cpenable & (1 << cp))) {
        gen_exception_cause(dc, COPROCESSOR0_DISABLED + cp);
        dc->is_jmp = DISAS_UPDATE;
        return false;
    }
    return true;
}

static void gen_jump_slot(DisasContext *dc, TCGv dest, int slot)
{
    tcg_gen_mov_i32(cpu_pc, dest);
    if (dc->icount) {
        tcg_gen_mov_i32(cpu_SR[ICOUNT], dc->next_icount);
    }
    if (dc->singlestep_enabled) {
        gen_exception(dc, EXCP_DEBUG);
    } else {
        if (slot >= 0) {
            tcg_gen_goto_tb(slot);
            tcg_gen_exit_tb((uintptr_t)dc->tb + slot);
        } else {
            tcg_gen_exit_tb(0);
        }
    }
    dc->is_jmp = DISAS_UPDATE;
}

static void gen_jump(DisasContext *dc, TCGv dest)
{
    gen_jump_slot(dc, dest, -1);
}

static void gen_jumpi(DisasContext *dc, uint32_t dest, int slot)
{
    TCGv_i32 tmp = tcg_const_i32(dest);
#ifndef CONFIG_USER_ONLY
    if (((dc->tb->pc ^ dest) & TARGET_PAGE_MASK) != 0) {
        slot = -1;
    }
#endif
    gen_jump_slot(dc, tmp, slot);
    tcg_temp_free(tmp);
}

static void gen_callw_slot(DisasContext *dc, int callinc, TCGv_i32 dest,
        int slot)
{
    TCGv_i32 tcallinc = tcg_const_i32(callinc);

    tcg_gen_deposit_i32(cpu_SR[PS], cpu_SR[PS],
            tcallinc, PS_CALLINC_SHIFT, PS_CALLINC_LEN);
    tcg_temp_free(tcallinc);
    tcg_gen_movi_i32(cpu_R[callinc << 2],
            (callinc << 30) | (dc->next_pc & 0x3fffffff));
    gen_jump_slot(dc, dest, slot);
}

static void gen_callw(DisasContext *dc, int callinc, TCGv_i32 dest)
{
    gen_callw_slot(dc, callinc, dest, -1);
}

static void gen_callwi(DisasContext *dc, int callinc, uint32_t dest, int slot)
{
    TCGv_i32 tmp = tcg_const_i32(dest);
#ifndef CONFIG_USER_ONLY
    if (((dc->tb->pc ^ dest) & TARGET_PAGE_MASK) != 0) {
        slot = -1;
    }
#endif
    gen_callw_slot(dc, callinc, tmp, slot);
    tcg_temp_free(tmp);
}

static bool gen_check_loop_end(DisasContext *dc, int slot)
{
    if (option_enabled(dc, XTENSA_OPTION_LOOP) &&
            !(dc->tb->flags & XTENSA_TBFLAG_EXCM) &&
            dc->next_pc == dc->lend) {
        TCGLabel *label = gen_new_label();

        tcg_gen_brcondi_i32(TCG_COND_EQ, cpu_SR[LCOUNT], 0, label);
        tcg_gen_subi_i32(cpu_SR[LCOUNT], cpu_SR[LCOUNT], 1);
        gen_jumpi(dc, dc->lbeg, slot);
        gen_set_label(label);
        gen_jumpi(dc, dc->next_pc, -1);
        return true;
    }
    return false;
}

static void gen_jumpi_check_loop_end(DisasContext *dc, int slot)
{
    if (!gen_check_loop_end(dc, slot)) {
        gen_jumpi(dc, dc->next_pc, slot);
    }
}

static void gen_brcond(DisasContext *dc, TCGCond cond,
                       TCGv_i32 t0, TCGv_i32 t1, uint32_t addr)
{
    TCGLabel *label = gen_new_label();

    tcg_gen_brcond_i32(cond, t0, t1, label);
    gen_jumpi_check_loop_end(dc, 0);
    gen_set_label(label);
    gen_jumpi(dc, addr, 1);
}

static void gen_brcondi(DisasContext *dc, TCGCond cond,
                        TCGv_i32 t0, uint32_t t1, uint32_t addr)
{
    TCGv_i32 tmp = tcg_const_i32(t1);
    gen_brcond(dc, cond, t0, tmp, addr);
    tcg_temp_free(tmp);
}

static bool gen_rsr_ccount(DisasContext *dc, TCGv_i32 d, uint32_t sr)
{
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_helper_update_ccount(cpu_env);
    tcg_gen_mov_i32(d, cpu_SR[sr]);
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_end();
        return true;
    }
    return false;
}

static bool gen_rsr_ptevaddr(DisasContext *dc, TCGv_i32 d, uint32_t sr)
{
    tcg_gen_shri_i32(d, cpu_SR[EXCVADDR], 10);
    tcg_gen_or_i32(d, d, cpu_SR[sr]);
    tcg_gen_andi_i32(d, d, 0xfffffffc);
    return false;
}

static bool gen_rsr(DisasContext *dc, TCGv_i32 d, uint32_t sr)
{
    static bool (* const rsr_handler[256])(DisasContext *dc,
            TCGv_i32 d, uint32_t sr) = {
        [CCOUNT] = gen_rsr_ccount,
        [INTSET] = gen_rsr_ccount,
        [PTEVADDR] = gen_rsr_ptevaddr,
    };

    if (rsr_handler[sr]) {
        return rsr_handler[sr](dc, d, sr);
    } else {
        tcg_gen_mov_i32(d, cpu_SR[sr]);
        return false;
    }
}

static bool gen_wsr_lbeg(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    gen_helper_wsr_lbeg(cpu_env, s);
    gen_jumpi_check_loop_end(dc, 0);
    return false;
}

static bool gen_wsr_lend(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    gen_helper_wsr_lend(cpu_env, s);
    gen_jumpi_check_loop_end(dc, 0);
    return false;
}

static bool gen_wsr_sar(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    tcg_gen_andi_i32(cpu_SR[sr], s, 0x3f);
    if (dc->sar_m32_5bit) {
        tcg_gen_discard_i32(dc->sar_m32);
    }
    dc->sar_5bit = false;
    dc->sar_m32_5bit = false;
    return false;
}

static bool gen_wsr_br(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    tcg_gen_andi_i32(cpu_SR[sr], s, 0xffff);
    return false;
}

static bool gen_wsr_litbase(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    tcg_gen_andi_i32(cpu_SR[sr], s, 0xfffff001);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_acchi(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    tcg_gen_ext8s_i32(cpu_SR[sr], s);
    return false;
}

static bool gen_wsr_windowbase(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    gen_helper_wsr_windowbase(cpu_env, v);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_windowstart(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, (1 << dc->config->nareg / 4) - 1);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_ptevaddr(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, 0xffc00000);
    return false;
}

static bool gen_wsr_rasid(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    gen_helper_wsr_rasid(cpu_env, v);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_tlbcfg(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, 0x01130000);
    return false;
}

static bool gen_wsr_ibreakenable(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    gen_helper_wsr_ibreakenable(cpu_env, v);
    gen_jumpi_check_loop_end(dc, 0);
    return true;
}

static bool gen_wsr_memctl(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    gen_helper_wsr_memctl(cpu_env, v);
    return false;
}

static bool gen_wsr_atomctl(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, 0x3f);
    return false;
}

static bool gen_wsr_ibreaka(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    unsigned id = sr - IBREAKA;

    if (id < dc->config->nibreak) {
        TCGv_i32 tmp = tcg_const_i32(id);
        gen_helper_wsr_ibreaka(cpu_env, tmp, v);
        tcg_temp_free(tmp);
        gen_jumpi_check_loop_end(dc, 0);
        return true;
    }
    return false;
}

static bool gen_wsr_dbreaka(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    unsigned id = sr - DBREAKA;

    if (id < dc->config->ndbreak) {
        TCGv_i32 tmp = tcg_const_i32(id);
        gen_helper_wsr_dbreaka(cpu_env, tmp, v);
        tcg_temp_free(tmp);
    }
    return false;
}

static bool gen_wsr_dbreakc(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    unsigned id = sr - DBREAKC;

    if (id < dc->config->ndbreak) {
        TCGv_i32 tmp = tcg_const_i32(id);
        gen_helper_wsr_dbreakc(cpu_env, tmp, v);
        tcg_temp_free(tmp);
    }
    return false;
}

static bool gen_wsr_cpenable(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, 0xff);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static void gen_check_interrupts(DisasContext *dc)
{
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_helper_check_interrupts(cpu_env);
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_end();
    }
}

static bool gen_wsr_intset(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v,
            dc->config->inttype_mask[INTTYPE_SOFTWARE]);
    gen_check_interrupts(dc);
    gen_jumpi_check_loop_end(dc, 0);
    return true;
}

static bool gen_wsr_intclear(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    TCGv_i32 tmp = tcg_temp_new_i32();

    tcg_gen_andi_i32(tmp, v,
            dc->config->inttype_mask[INTTYPE_EDGE] |
            dc->config->inttype_mask[INTTYPE_NMI] |
            dc->config->inttype_mask[INTTYPE_SOFTWARE]);
    tcg_gen_andc_i32(cpu_SR[INTSET], cpu_SR[INTSET], tmp);
    tcg_temp_free(tmp);
    gen_check_interrupts(dc);
    gen_jumpi_check_loop_end(dc, 0);
    return true;
}

static bool gen_wsr_intenable(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_mov_i32(cpu_SR[sr], v);
    gen_check_interrupts(dc);
    gen_jumpi_check_loop_end(dc, 0);
    return true;
}

static bool gen_wsr_ps(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    uint32_t mask = PS_WOE | PS_CALLINC | PS_OWB |
        PS_UM | PS_EXCM | PS_INTLEVEL;

    if (option_enabled(dc, XTENSA_OPTION_MMU)) {
        mask |= PS_RING;
    }
    tcg_gen_andi_i32(cpu_SR[sr], v, mask);
    gen_check_interrupts(dc);
    /* This can change mmu index and tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_ccount(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_helper_wsr_ccount(cpu_env, v);
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_end();
        gen_jumpi_check_loop_end(dc, 0);
        return true;
    }
    return false;
}

static bool gen_wsr_icount(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    if (dc->icount) {
        tcg_gen_mov_i32(dc->next_icount, v);
    } else {
        tcg_gen_mov_i32(cpu_SR[sr], v);
    }
    return false;
}

static bool gen_wsr_icountlevel(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    tcg_gen_andi_i32(cpu_SR[sr], v, 0xf);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
    return true;
}

static bool gen_wsr_ccompare(DisasContext *dc, uint32_t sr, TCGv_i32 v)
{
    uint32_t id = sr - CCOMPARE;
    bool ret = false;

    if (id < dc->config->nccompare) {
        uint32_t int_bit = 1 << dc->config->timerint[id];
        TCGv_i32 tmp = tcg_const_i32(id);

        tcg_gen_mov_i32(cpu_SR[sr], v);
        tcg_gen_andi_i32(cpu_SR[INTSET], cpu_SR[INTSET], ~int_bit);
        if (dc->tb->cflags & CF_USE_ICOUNT) {
            gen_io_start();
        }
        gen_helper_update_ccompare(cpu_env, tmp);
        if (dc->tb->cflags & CF_USE_ICOUNT) {
            gen_io_end();
            gen_jumpi_check_loop_end(dc, 0);
            ret = true;
        }
        tcg_temp_free(tmp);
    }
    return ret;
}

static bool gen_wsr(DisasContext *dc, uint32_t sr, TCGv_i32 s)
{
    static bool (* const wsr_handler[256])(DisasContext *dc,
            uint32_t sr, TCGv_i32 v) = {
        [LBEG] = gen_wsr_lbeg,
        [LEND] = gen_wsr_lend,
        [SAR] = gen_wsr_sar,
        [BR] = gen_wsr_br,
        [LITBASE] = gen_wsr_litbase,
        [ACCHI] = gen_wsr_acchi,
        [WINDOW_BASE] = gen_wsr_windowbase,
        [WINDOW_START] = gen_wsr_windowstart,
        [PTEVADDR] = gen_wsr_ptevaddr,
        [RASID] = gen_wsr_rasid,
        [ITLBCFG] = gen_wsr_tlbcfg,
        [DTLBCFG] = gen_wsr_tlbcfg,
        [IBREAKENABLE] = gen_wsr_ibreakenable,
        [MEMCTL] = gen_wsr_memctl,
        [ATOMCTL] = gen_wsr_atomctl,
        [IBREAKA] = gen_wsr_ibreaka,
        [IBREAKA + 1] = gen_wsr_ibreaka,
        [DBREAKA] = gen_wsr_dbreaka,
        [DBREAKA + 1] = gen_wsr_dbreaka,
        [DBREAKC] = gen_wsr_dbreakc,
        [DBREAKC + 1] = gen_wsr_dbreakc,
        [CPENABLE] = gen_wsr_cpenable,
        [INTSET] = gen_wsr_intset,
        [INTCLEAR] = gen_wsr_intclear,
        [INTENABLE] = gen_wsr_intenable,
        [PS] = gen_wsr_ps,
        [CCOUNT] = gen_wsr_ccount,
        [ICOUNT] = gen_wsr_icount,
        [ICOUNTLEVEL] = gen_wsr_icountlevel,
        [CCOMPARE] = gen_wsr_ccompare,
        [CCOMPARE + 1] = gen_wsr_ccompare,
        [CCOMPARE + 2] = gen_wsr_ccompare,
    };

    if (wsr_handler[sr]) {
        return wsr_handler[sr](dc, sr, s);
    } else {
        tcg_gen_mov_i32(cpu_SR[sr], s);
        return false;
    }
}

static void gen_wur(uint32_t ur, TCGv_i32 s)
{
    switch (ur) {
    case FCR:
        gen_helper_wur_fcr(cpu_env, s);
        break;

    case FSR:
        tcg_gen_andi_i32(cpu_UR[ur], s, 0xffffff80);
        break;

    default:
        tcg_gen_mov_i32(cpu_UR[ur], s);
        break;
    }
}

static void gen_load_store_alignment(DisasContext *dc, int shift,
        TCGv_i32 addr, bool no_hw_alignment)
{
    if (!option_enabled(dc, XTENSA_OPTION_UNALIGNED_EXCEPTION)) {
        tcg_gen_andi_i32(addr, addr, ~0 << shift);
    } else if (option_enabled(dc, XTENSA_OPTION_HW_ALIGNMENT) &&
            no_hw_alignment) {
        TCGLabel *label = gen_new_label();
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_andi_i32(tmp, addr, ~(~0 << shift));
        tcg_gen_brcondi_i32(TCG_COND_EQ, tmp, 0, label);
        gen_exception_cause_vaddr(dc, LOAD_STORE_ALIGNMENT_CAUSE, addr);
        gen_set_label(label);
        tcg_temp_free(tmp);
    }
}

static void gen_waiti(DisasContext *dc, uint32_t imm4)
{
    TCGv_i32 pc = tcg_const_i32(dc->next_pc);
    TCGv_i32 intlevel = tcg_const_i32(imm4);

    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_start();
    }
    gen_helper_waiti(cpu_env, pc, intlevel);
    if (dc->tb->cflags & CF_USE_ICOUNT) {
        gen_io_end();
    }
    tcg_temp_free(pc);
    tcg_temp_free(intlevel);
    gen_jumpi_check_loop_end(dc, 0);
}

static bool gen_window_check1(DisasContext *dc, unsigned r1)
{
    if (r1 / 4 > dc->window) {
        TCGv_i32 pc = tcg_const_i32(dc->pc);
        TCGv_i32 w = tcg_const_i32(r1 / 4);

        gen_helper_window_check(cpu_env, pc, w);
        dc->is_jmp = DISAS_UPDATE;
        return false;
    }
    return true;
}

static bool gen_window_check2(DisasContext *dc, unsigned r1, unsigned r2)
{
    return gen_window_check1(dc, r1 > r2 ? r1 : r2);
}

static bool gen_window_check3(DisasContext *dc, unsigned r1, unsigned r2,
        unsigned r3)
{
    return gen_window_check2(dc, r1, r2 > r3 ? r2 : r3);
}

static TCGv_i32 gen_mac16_m(TCGv_i32 v, bool hi, bool is_unsigned)
{
    TCGv_i32 m = tcg_temp_new_i32();

    if (hi) {
        (is_unsigned ? tcg_gen_shri_i32 : tcg_gen_sari_i32)(m, v, 16);
    } else {
        (is_unsigned ? tcg_gen_ext16u_i32 : tcg_gen_ext16s_i32)(m, v);
    }
    return m;
}

static inline unsigned xtensa_op0_insn_len(DisasContext *dc, uint8_t op0)
{
    return xtensa_isa_length_from_chars(dc->config->isa, &op0);
}

static void disas_xtensa_insn(CPUXtensaState *env, DisasContext *dc)
{
    xtensa_isa isa = dc->config->isa;
    unsigned char b[16] = {cpu_ldub_code(env, dc->pc)};
    unsigned len = xtensa_op0_insn_len(dc, b[0]);
    xtensa_format fmt;
    unsigned slot, slots;
    unsigned i;

    if (len == XTENSA_UNDEFINED) {
        goto invalid_opcode;
    }

    dc->next_pc = dc->pc + len;
    for (i = 1; i < len; ++i) {
        b[i] = cpu_ldub_code(env, dc->pc + i);
    }
    xtensa_insnbuf_from_chars(isa, dc->insnbuf, b, len);
    fmt = xtensa_format_decode(isa, dc->insnbuf);
    slots = xtensa_format_num_slots(isa, fmt);
//        fprintf(stderr, slots > 1 ? "0x%08x : { " : "0x%08x : ", dc->pc);
    for (slot = 0; slot < slots; ++slot) {
        xtensa_opcode opc;
        unsigned opnd, vopnd, opnds;
        uint32_t raw_arg[16];
        uint32_t arg[16];
        XtensaOpcodeMap *map;

        dc->raw_arg = raw_arg;

        xtensa_format_get_slot(isa, fmt, slot, dc->insnbuf, dc->slotbuf);
        opc = xtensa_opcode_decode(isa, fmt, slot, dc->slotbuf);
        opnds = xtensa_opcode_num_operands(isa, opc);

//            fprintf(stderr, "%s%s", slot ? "; " : "",
//                    xtensa_opcode_name(isa, opc));
        for (opnd = vopnd = 0; opnd < opnds; ++opnd) {
            if (xtensa_operand_is_visible(isa, opc, opnd)) {
                uint32_t v;

//                    fprintf(stderr, vopnd ? ", " : "\t");
                xtensa_operand_get_field(isa, opc, opnd, fmt, slot,
                                         dc->slotbuf, &v);
                xtensa_operand_decode(isa, opc, opnd, &v);
                raw_arg[vopnd] = v;
                if (xtensa_operand_is_register(isa, opc, opnd)) {
                    xtensa_regfile rf = xtensa_operand_regfile(isa, opc, opnd);
//                        fprintf(stderr, "%s%d", xtensa_regfile_shortname(isa, rf), v);
                } else {
                    if (xtensa_operand_is_PCrelative(isa, opc, opnd)) {
                        xtensa_operand_undo_reloc(isa, opc, opnd, &v, dc->pc);
//                            fprintf(stderr, "0x%x", v);
                    } else {
//                            fprintf(stderr, "%d", v);
                    }
                }
                arg[vopnd] = v;
                ++vopnd;
            }
        }
        map = dc->config->opcode_map[opc];
        if (map) {
            map->translator(dc, arg, map->par);
        } else {
//                fprintf(stderr, " -- old\n");
        }
    }
//        fprintf(stderr, slots > 1 ? " }\n" : "\n");

    if (dc->is_jmp == DISAS_NEXT) {
        gen_check_loop_end(dc, 0);
    }
    dc->pc = dc->next_pc;

    return;

invalid_opcode:
    qemu_log_mask(LOG_GUEST_ERROR, "INVALID(pc = %08x)\n", dc->pc);
    gen_exception_cause(dc, ILLEGAL_INSTRUCTION_CAUSE);
}

static inline unsigned xtensa_insn_len(CPUXtensaState *env, DisasContext *dc)
{
    uint8_t b0 = cpu_ldub_code(env, dc->pc);
    return xtensa_op0_insn_len(dc, b0);
}

static void gen_ibreak_check(CPUXtensaState *env, DisasContext *dc)
{
    unsigned i;

    for (i = 0; i < dc->config->nibreak; ++i) {
        if ((env->sregs[IBREAKENABLE] & (1 << i)) &&
                env->sregs[IBREAKA + i] == dc->pc) {
            gen_debug_exception(dc, DEBUGCAUSE_IB);
            break;
        }
    }
}

void gen_intermediate_code(CPUXtensaState *env, TranslationBlock *tb)
{
    XtensaCPU *cpu = xtensa_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    DisasContext dc;
    int insn_count = 0;
    int max_insns = tb->cflags & CF_COUNT_MASK;
    uint32_t pc_start = tb->pc;
    uint32_t next_page_start =
        (pc_start & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;

    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }

    dc.config = env->config;
    dc.singlestep_enabled = cs->singlestep_enabled;
    dc.tb = tb;
    dc.pc = pc_start;
    dc.ring = tb->flags & XTENSA_TBFLAG_RING_MASK;
    dc.cring = (tb->flags & XTENSA_TBFLAG_EXCM) ? 0 : dc.ring;
    dc.lbeg = env->sregs[LBEG];
    dc.lend = env->sregs[LEND];
    dc.is_jmp = DISAS_NEXT;
    dc.debug = tb->flags & XTENSA_TBFLAG_DEBUG;
    dc.icount = tb->flags & XTENSA_TBFLAG_ICOUNT;
    dc.cpenable = (tb->flags & XTENSA_TBFLAG_CPENABLE_MASK) >>
        XTENSA_TBFLAG_CPENABLE_SHIFT;
    dc.window = ((tb->flags & XTENSA_TBFLAG_WINDOW_MASK) >>
                 XTENSA_TBFLAG_WINDOW_SHIFT);

    if (dc.config->isa) {
        dc.insnbuf = xtensa_insnbuf_alloc(dc.config->isa);
        dc.slotbuf = xtensa_insnbuf_alloc(dc.config->isa);
    }

    init_litbase(&dc);
    init_sar_tracker(&dc);
    if (dc.icount) {
        dc.next_icount = tcg_temp_local_new_i32();
    }

    gen_tb_start(tb);

    if ((tb->cflags & CF_USE_ICOUNT) &&
        (tb->flags & XTENSA_TBFLAG_YIELD)) {
        tcg_gen_insn_start(dc.pc);
        ++insn_count;
        gen_exception(&dc, EXCP_YIELD);
        dc.is_jmp = DISAS_UPDATE;
        goto done;
    }
    if (tb->flags & XTENSA_TBFLAG_EXCEPTION) {
        tcg_gen_insn_start(dc.pc);
        ++insn_count;
        gen_exception(&dc, EXCP_DEBUG);
        dc.is_jmp = DISAS_UPDATE;
        goto done;
    }

    do {
        tcg_gen_insn_start(dc.pc);
        ++insn_count;

        if (unlikely(cpu_breakpoint_test(cs, dc.pc, BP_ANY))) {
            tcg_gen_movi_i32(cpu_pc, dc.pc);
            gen_exception(&dc, EXCP_DEBUG);
            dc.is_jmp = DISAS_UPDATE;
            /* The address covered by the breakpoint must be included in
               [tb->pc, tb->pc + tb->size) in order to for it to be
               properly cleared -- thus we increment the PC here so that
               the logic setting tb->size below does the right thing.  */
            dc.pc += 2;
            break;
        }

        if (insn_count == max_insns && (tb->cflags & CF_LAST_IO)) {
            gen_io_start();
        }

        if (dc.icount) {
            TCGLabel *label = gen_new_label();

            tcg_gen_addi_i32(dc.next_icount, cpu_SR[ICOUNT], 1);
            tcg_gen_brcondi_i32(TCG_COND_NE, dc.next_icount, 0, label);
            tcg_gen_mov_i32(dc.next_icount, cpu_SR[ICOUNT]);
            if (dc.debug) {
                gen_debug_exception(&dc, DEBUGCAUSE_IC);
            }
            gen_set_label(label);
        }

        if (dc.debug) {
            gen_ibreak_check(env, &dc);
        }

        disas_xtensa_insn(env, &dc);
        if (dc.icount) {
            tcg_gen_mov_i32(cpu_SR[ICOUNT], dc.next_icount);
        }
        if (cs->singlestep_enabled) {
            tcg_gen_movi_i32(cpu_pc, dc.pc);
            gen_exception(&dc, EXCP_DEBUG);
            break;
        }
    } while (dc.is_jmp == DISAS_NEXT &&
            insn_count < max_insns &&
            dc.pc < next_page_start &&
            dc.pc + xtensa_insn_len(env, &dc) <= next_page_start &&
            !tcg_op_buf_full());
done:
    reset_litbase(&dc);
    reset_sar_tracker(&dc);
    if (dc.icount) {
        tcg_temp_free(dc.next_icount);
    }
    if (dc.config->isa) {
        xtensa_insnbuf_free(dc.config->isa, dc.insnbuf);
        xtensa_insnbuf_free(dc.config->isa, dc.slotbuf);
    }

    if (tb->cflags & CF_LAST_IO) {
        gen_io_end();
    }

    if (dc.is_jmp == DISAS_NEXT) {
        gen_jumpi(&dc, dc.pc, 0);
    }
    gen_tb_end(tb, insn_count);

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(pc_start)) {
        qemu_log_lock();
        qemu_log("----------------\n");
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(cs, pc_start, dc.pc - pc_start, 0);
        qemu_log("\n");
        qemu_log_unlock();
    }
#endif
    tb->size = dc.pc - pc_start;
    tb->icount = insn_count;
}

void xtensa_cpu_dump_state(CPUState *cs, FILE *f,
                           fprintf_function cpu_fprintf, int flags)
{
    XtensaCPU *cpu = XTENSA_CPU(cs);
    CPUXtensaState *env = &cpu->env;
    int i, j;

    cpu_fprintf(f, "PC=%08x\n\n", env->pc);

    for (i = j = 0; i < 256; ++i) {
        if (xtensa_option_bits_enabled(env->config, sregnames[i].opt_bits)) {
            cpu_fprintf(f, "%12s=%08x%c", sregnames[i].name, env->sregs[i],
                    (j++ % 4) == 3 ? '\n' : ' ');
        }
    }

    cpu_fprintf(f, (j % 4) == 0 ? "\n" : "\n\n");

    for (i = j = 0; i < 256; ++i) {
        if (xtensa_option_bits_enabled(env->config, uregnames[i].opt_bits)) {
            cpu_fprintf(f, "%s=%08x%c", uregnames[i].name, env->uregs[i],
                    (j++ % 4) == 3 ? '\n' : ' ');
        }
    }

    cpu_fprintf(f, (j % 4) == 0 ? "\n" : "\n\n");

    for (i = 0; i < 16; ++i) {
        cpu_fprintf(f, " A%02d=%08x%c", i, env->regs[i],
                (i % 4) == 3 ? '\n' : ' ');
    }

    cpu_fprintf(f, "\n");

    for (i = 0; i < env->config->nareg; ++i) {
        cpu_fprintf(f, "AR%02d=%08x%c", i, env->phys_regs[i],
                (i % 4) == 3 ? '\n' : ' ');
    }

    if (xtensa_option_enabled(env->config, XTENSA_OPTION_FP_COPROCESSOR)) {
        cpu_fprintf(f, "\n");

        for (i = 0; i < 16; ++i) {
            cpu_fprintf(f, "F%02d=%08x (%+10.8e)%c", i,
                    float32_val(env->fregs[i].f32[FP_F32_LOW]),
                    *(float *)(env->fregs[i].f32 + FP_F32_LOW),
                    (i % 2) == 1 ? '\n' : ' ');
        }
    }
}

void restore_state_to_opc(CPUXtensaState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
}

static void translate_abs(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 zero = tcg_const_i32(0);
        TCGv_i32 neg = tcg_temp_new_i32();

        tcg_gen_neg_i32(neg, cpu_R[arg[1]]);
        tcg_gen_movcond_i32(TCG_COND_GE, cpu_R[arg[0]],
                            cpu_R[arg[1]], zero, cpu_R[arg[1]], neg);
        tcg_temp_free(neg);
        tcg_temp_free(zero);
    }
}

static void translate_add(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_add_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_addi(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_addi_i32(cpu_R[arg[0]], cpu_R[arg[1]], arg[2]);
    }
}

static void translate_addx(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_shli_i32(tmp, cpu_R[arg[1]], par[0]);
        tcg_gen_add_i32(cpu_R[arg[0]], tmp, cpu_R[arg[2]]);
        tcg_temp_free(tmp);
    }
}

static void translate_all(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    uint32_t shift = par[1];
    TCGv_i32 mask = tcg_const_i32(((1 << shift) - 1) << arg[1]);
    TCGv_i32 tmp = tcg_temp_new_i32();

    tcg_gen_and_i32(tmp, cpu_SR[BR], mask);
    if (par[0]) {
        tcg_gen_addi_i32(tmp, tmp, 1 << arg[1]);
    } else {
        tcg_gen_add_i32(tmp, tmp, mask);
    }
    tcg_gen_shri_i32(tmp, tmp, arg[1] + shift);
    tcg_gen_deposit_i32(cpu_SR[BR], cpu_SR[BR],
                        tmp, arg[0], 1);
    tcg_temp_free(mask);
    tcg_temp_free(tmp);
}

static void translate_and(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_and_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_ball(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_and_i32(tmp, cpu_R[arg[0]], cpu_R[arg[1]]);
        gen_brcond(dc, par[0], tmp, cpu_R[arg[1]], arg[2]);
        tcg_temp_free(tmp);
    }
}

static void translate_bany(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_and_i32(tmp, cpu_R[arg[0]], cpu_R[arg[1]]);
        gen_brcondi(dc, par[0], tmp, 0, arg[2]);
        tcg_temp_free(tmp);
    }
}

static void translate_b(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        gen_brcond(dc, par[0], cpu_R[arg[0]], cpu_R[arg[1]], arg[2]);
    }
}

static void translate_bb(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
#ifdef TARGET_WORDS_BIGENDIAN
        TCGv_i32 bit = tcg_const_i32(0x80000000u);
#else
        TCGv_i32 bit = tcg_const_i32(0x00000001u);
#endif
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_andi_i32(tmp, cpu_R[arg[1]], 0x1f);
#ifdef TARGET_WORDS_BIGENDIAN
        tcg_gen_shr_i32(bit, bit, tmp);
#else
        tcg_gen_shl_i32(bit, bit, tmp);
#endif
        tcg_gen_and_i32(tmp, cpu_R[arg[0]], bit);
        gen_brcondi(dc, par[0], tmp, 0, arg[2]);
        tcg_temp_free(tmp);
        tcg_temp_free(bit);
    }
}

static void translate_bbi(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
#ifdef TARGET_WORDS_BIGENDIAN
        tcg_gen_andi_i32(tmp, cpu_R[arg[0]], 0x80000000u >> arg[1]);
#else
        tcg_gen_andi_i32(tmp, cpu_R[arg[0]], 0x00000001u << arg[1]);
#endif
        gen_brcondi(dc, par[0], tmp, 0, arg[2]);
        tcg_temp_free(tmp);
    }
}

static void translate_bi(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        gen_brcondi(dc, par[0], cpu_R[arg[0]], arg[1], arg[2]);
    }
}

static void translate_bz(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        gen_brcondi(dc, par[0], cpu_R[arg[0]], 0, arg[1]);
    }
}

enum {
    BOOLEAN_AND,
    BOOLEAN_ANDC,
    BOOLEAN_OR,
    BOOLEAN_ORC,
    BOOLEAN_XOR,
};

static void translate_boolean(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    static void (* const op[])(TCGv_i32, TCGv_i32, TCGv_i32) = {
        [BOOLEAN_AND] = tcg_gen_and_i32,
        [BOOLEAN_ANDC] = tcg_gen_andc_i32,
        [BOOLEAN_OR] = tcg_gen_or_i32,
        [BOOLEAN_ORC] = tcg_gen_orc_i32,
        [BOOLEAN_XOR] = tcg_gen_xor_i32,
    };

    TCGv_i32 tmp1 = tcg_temp_new_i32();
    TCGv_i32 tmp2 = tcg_temp_new_i32();

    tcg_gen_shri_i32(tmp1, cpu_SR[BR], arg[1]);
    tcg_gen_shri_i32(tmp2, cpu_SR[BR], arg[2]);
    op[par[0]](tmp1, tmp1, tmp2);
    tcg_gen_deposit_i32(cpu_SR[BR], cpu_SR[BR], tmp1, arg[0], 1);
    tcg_temp_free(tmp1);
    tcg_temp_free(tmp2);
}

static void translate_bp(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    TCGv_i32 tmp = tcg_temp_new_i32();

    tcg_gen_andi_i32(tmp, cpu_SR[BR], 1 << arg[0]);
    gen_brcondi(dc, par[0], tmp, 0, arg[1]);
    tcg_temp_free(tmp);
}

static void translate_break(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (dc->debug) {
        gen_debug_exception(dc, par[0]);
    }
}

static void translate_call0(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    tcg_gen_movi_i32(cpu_R[0], dc->next_pc);
    gen_jumpi(dc, arg[0], 0);
}

static void translate_callw(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, par[0] << 2)) {
        gen_callwi(dc, par[0], arg[0], 0);
    }
}

static void translate_callx0(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_mov_i32(tmp, cpu_R[arg[0]]);
        tcg_gen_movi_i32(cpu_R[0], dc->next_pc);
        gen_jump(dc, tmp);
        tcg_temp_free(tmp);
    }
}

static void translate_callxw(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], par[0] << 2)) {
        TCGv_i32 tmp = tcg_temp_new_i32();

        tcg_gen_mov_i32(tmp, cpu_R[arg[0]]);
        gen_callw(dc, par[0], tmp);
        tcg_temp_free(tmp);
    }
}

static void translate_clamps(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 tmp1 = tcg_const_i32(-1u << arg[2]);
        TCGv_i32 tmp2 = tcg_const_i32((1 << arg[2]) - 1);

        tcg_gen_movcond_i32(TCG_COND_GT, tmp1,
                            cpu_R[arg[1]], tmp1, cpu_R[arg[1]], tmp1);
        tcg_gen_movcond_i32(TCG_COND_LT, cpu_R[arg[0]],
                            tmp1, tmp2, tmp1, tmp2);
        tcg_temp_free(tmp1);
        tcg_temp_free(tmp2);
    }
}

/* par[0]: privileged, par[1]: check memory access */
static void translate_dcache(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if ((!par[0] || gen_check_privilege(dc)) &&
        gen_window_check1(dc, arg[0]) && par[1]) {
        TCGv_i32 addr = tcg_temp_new_i32();
        TCGv_i32 res = tcg_temp_new_i32();

        tcg_gen_addi_i32(addr, cpu_R[arg[0]], arg[1]);
        tcg_gen_qemu_ld8u(res, addr, dc->cring);
        tcg_temp_free(addr);
        tcg_temp_free(res);
    }
}

static void translate_depbits(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_deposit_i32(cpu_R[arg[1]], cpu_R[arg[1]], cpu_R[arg[0]],
                            arg[2], arg[3]);
    }
}

static void translate_entry(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    TCGv_i32 pc = tcg_const_i32(dc->pc);
    TCGv_i32 s = tcg_const_i32(arg[0]);
    TCGv_i32 imm = tcg_const_i32(arg[1]);
    gen_helper_entry(cpu_env, pc, s, imm);
    tcg_temp_free(imm);
    tcg_temp_free(s);
    tcg_temp_free(pc);
    /* This can change tb->flags, so exit tb */
    gen_jumpi_check_loop_end(dc, -1);
}

static void translate_extui(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        int maskimm = (1 << arg[3]) - 1;

        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_shri_i32(tmp, cpu_R[arg[1]], arg[2]);
        tcg_gen_andi_i32(cpu_R[arg[0]], tmp, maskimm);
        tcg_temp_free(tmp);
    }
}

/* par[0]: privileged, par[1]: check memory access */
static void translate_icache(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if ((!par[0] || gen_check_privilege(dc)) &&
        gen_window_check1(dc, arg[0]) && par[1]) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_movi_i32(cpu_pc, dc->pc);
        tcg_gen_addi_i32(addr, cpu_R[arg[0]], arg[1]);
        gen_helper_itlb_hit_test(cpu_env, addr);
        tcg_temp_free(addr);
    }
}

static void translate_itlb(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check1(dc, arg[0])) {
        TCGv_i32 dtlb = tcg_const_i32(par[0]);

        gen_helper_itlb(cpu_env, cpu_R[arg[0]], dtlb);
        /* This could change memory mapping, so exit tb */
        gen_jumpi_check_loop_end(dc, -1);
        tcg_temp_free(dtlb);
    }
}

static void translate_ill(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    gen_exception_cause(dc, ILLEGAL_INSTRUCTION_CAUSE);
}

static void translate_j(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    gen_jumpi(dc, arg[0], 0);
}

static void translate_jx(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        gen_jump(dc, cpu_R[arg[0]]);
    }
}

static void translate_l32e(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_addi_i32(addr, cpu_R[arg[1]], arg[2]);
        gen_load_store_alignment(dc, 2, addr, false);
        tcg_gen_qemu_ld_tl(cpu_R[arg[0]], addr, dc->ring, MO_TEUL);
        tcg_temp_free(addr);
    }
}

static void translate_ldst(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_addi_i32(addr, cpu_R[arg[1]], arg[2]);
        if (par[0] & MO_SIZE) {
            gen_load_store_alignment(dc, par[0] & MO_SIZE, addr, par[1]);
        }
        if (par[2]) {
            tcg_gen_qemu_st_tl(cpu_R[arg[0]], addr, dc->cring, par[0]);
        } else {
            tcg_gen_qemu_ld_tl(cpu_R[arg[0]], addr, dc->cring, par[0]);
        }
        tcg_temp_free(addr);
    }
}

static void translate_l32r(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = (dc->tb->flags & XTENSA_TBFLAG_LITBASE) ?
                       tcg_const_i32(dc->raw_arg[1] - 1) :
                       tcg_const_i32(arg[1]);

        if (dc->tb->flags & XTENSA_TBFLAG_LITBASE) {
            tcg_gen_add_i32(tmp, tmp, dc->litbase);
        }
        tcg_gen_qemu_ld32u(cpu_R[arg[0]], tmp, dc->cring);
        tcg_temp_free(tmp);
    }
}

static void translate_loop(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        uint32_t lend = arg[1];
        TCGv_i32 tmp = tcg_const_i32(lend);

        tcg_gen_subi_i32(cpu_SR[LCOUNT], cpu_R[arg[0]], 1);
        tcg_gen_movi_i32(cpu_SR[LBEG], dc->next_pc);
        gen_helper_wsr_lend(cpu_env, tmp);
        tcg_temp_free(tmp);

        if (par[0] != TCG_COND_NEVER) {
            TCGLabel *label = gen_new_label();
            tcg_gen_brcondi_i32(par[0], cpu_R[arg[0]], 0, label);
            gen_jumpi(dc, lend, 1);
            gen_set_label(label);
        }

        gen_jumpi(dc, dc->next_pc, 0);
    }
}

enum {
    MAC16_UMUL,
    MAC16_MUL,
    MAC16_MULA,
    MAC16_MULS,
    MAC16_NONE,
};

enum {
    MAC16_LL,
    MAC16_HL,
    MAC16_LH,
    MAC16_HH,

    MAC16_HX = 0x1,
    MAC16_XH = 0x2,
};

enum {
    MAC16_AA,
    MAC16_AD,
    MAC16_DA,
    MAC16_DD,

    MAC16_XD = 0x1,
    MAC16_DX = 0x2,
};

static void translate_mac16(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    int op = par[0];
    bool is_m1_sr = par[1] & MAC16_DX;
    bool is_m2_sr = par[1] & MAC16_XD;
    unsigned half = par[2];
    uint32_t ld_offset = par[3];
    unsigned off = ld_offset ? 2 : 0;
    uint32_t ar[3] = {0};
    unsigned n_ar = 0;

    if (op != MAC16_NONE) {
        if (!is_m1_sr) {
            ar[n_ar++] = arg[off];
        }
        if (!is_m2_sr) {
            ar[n_ar++] = arg[off + 1];
        }
    }

    if (ld_offset) {
        ar[n_ar++] = arg[1];
    }

    if (gen_window_check3(dc, ar[0], ar[1], ar[2])) {
        TCGv_i32 vaddr = tcg_temp_new_i32();
        TCGv_i32 mem32 = tcg_temp_new_i32();

        if (ld_offset) {
            tcg_gen_addi_i32(vaddr, cpu_R[arg[1]], ld_offset);
            gen_load_store_alignment(dc, 2, vaddr, false);
            tcg_gen_qemu_ld32u(mem32, vaddr, dc->cring);
        }
        if (op != MAC16_NONE) {
            TCGv_i32 m1 = gen_mac16_m(is_m1_sr ?
                                      cpu_SR[MR + arg[off]] :
                                      cpu_R[arg[off]],
                                      half & MAC16_HX, op == MAC16_UMUL);
            TCGv_i32 m2 = gen_mac16_m(is_m2_sr ?
                                      cpu_SR[MR + arg[off + 1]] :
                                      cpu_R[arg[off + 1]],
                                      half & MAC16_XH, op == MAC16_UMUL);

            if (op == MAC16_MUL || op == MAC16_UMUL) {
                tcg_gen_mul_i32(cpu_SR[ACCLO], m1, m2);
                if (op == MAC16_UMUL) {
                    tcg_gen_movi_i32(cpu_SR[ACCHI], 0);
                } else {
                    tcg_gen_sari_i32(cpu_SR[ACCHI], cpu_SR[ACCLO], 31);
                }
            } else {
                TCGv_i32 lo = tcg_temp_new_i32();
                TCGv_i32 hi = tcg_temp_new_i32();

                tcg_gen_mul_i32(lo, m1, m2);
                tcg_gen_sari_i32(hi, lo, 31);
                if (op == MAC16_MULA) {
                    tcg_gen_add2_i32(cpu_SR[ACCLO], cpu_SR[ACCHI],
                                     cpu_SR[ACCLO], cpu_SR[ACCHI],
                                     lo, hi);
                } else {
                    tcg_gen_sub2_i32(cpu_SR[ACCLO], cpu_SR[ACCHI],
                                     cpu_SR[ACCLO], cpu_SR[ACCHI],
                                     lo, hi);
                }
                tcg_gen_ext8s_i32(cpu_SR[ACCHI], cpu_SR[ACCHI]);

                tcg_temp_free_i32(lo);
                tcg_temp_free_i32(hi);
            }
            tcg_temp_free(m1);
            tcg_temp_free(m2);
        }
        if (ld_offset) {
            tcg_gen_mov_i32(cpu_R[arg[1]], vaddr);
            tcg_gen_mov_i32(cpu_SR[MR + arg[0]], mem32);
        }
        tcg_temp_free(vaddr);
        tcg_temp_free(mem32);
    }
}

static void translate_minmax(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_movcond_i32(par[0], cpu_R[arg[0]],
                            cpu_R[arg[1]], cpu_R[arg[2]],
                            cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_mov(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_mov_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
    }
}

static void translate_movcond(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i32 zero = tcg_const_i32(0);

        tcg_gen_movcond_i32(par[0], cpu_R[arg[0]],
                            cpu_R[arg[2]], zero, cpu_R[arg[1]], cpu_R[arg[0]]);
        tcg_temp_free(zero);
    }
}

static void translate_movi(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        tcg_gen_movi_i32(cpu_R[arg[0]], arg[1]);
    }
}

static void translate_movp(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 zero = tcg_const_i32(0);
        TCGv_i32 tmp = tcg_temp_new_i32();

        tcg_gen_andi_i32(tmp, cpu_SR[BR], 1 << arg[2]);
        tcg_gen_movcond_i32(par[0],
                            cpu_R[arg[0]], tmp, zero,
                            cpu_R[arg[1]], cpu_R[arg[0]]);
        tcg_temp_free(tmp);
        tcg_temp_free(zero);
    }
}

static void translate_movsp(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 pc = tcg_const_i32(dc->pc);
        gen_helper_movsp(cpu_env, pc);
        tcg_gen_mov_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
        tcg_temp_free(pc);
    }
}

static void translate_mul16(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i32 v1 = tcg_temp_new_i32();
        TCGv_i32 v2 = tcg_temp_new_i32();

        if (par[0]) {
            tcg_gen_ext16s_i32(v1, cpu_R[arg[1]]);
            tcg_gen_ext16s_i32(v2, cpu_R[arg[2]]);
        } else {
            tcg_gen_ext16u_i32(v1, cpu_R[arg[1]]);
            tcg_gen_ext16u_i32(v2, cpu_R[arg[2]]);
        }
        tcg_gen_mul_i32(cpu_R[arg[0]], v1, v2);
        tcg_temp_free(v2);
        tcg_temp_free(v1);
    }
}

static void translate_mull(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_mul_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_mulh(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i32 lo = tcg_temp_new();

        if (par[0]) {
            tcg_gen_muls2_i32(lo, cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
        } else {
            tcg_gen_mulu2_i32(lo, cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
        }
        tcg_temp_free(lo);
    }
}

static void translate_neg(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_neg_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
    }
}

static void translate_nop(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
}

static void translate_nsa(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_clrsb_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
    }
}

static void translate_nsau(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_clzi_i32(cpu_R[arg[0]], cpu_R[arg[1]], 32);
    }
}

static void translate_or(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_or_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_ptlb(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 dtlb = tcg_const_i32(par[0]);

        tcg_gen_movi_i32(cpu_pc, dc->pc);
        gen_helper_ptlb(cpu_R[arg[0]], cpu_env, cpu_R[arg[1]], dtlb);
        tcg_temp_free(dtlb);
    }
}

static void gen_zero_check(DisasContext *dc, uint32_t arg[])
{
    TCGLabel *label = gen_new_label();

    tcg_gen_brcondi_i32(TCG_COND_NE, cpu_R[arg[2]], 0, label);
    gen_exception_cause(dc, INTEGER_DIVIDE_BY_ZERO_CAUSE);
    gen_set_label(label);
}

static void translate_quos(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGLabel *label1 = gen_new_label();
        TCGLabel *label2 = gen_new_label();

        gen_zero_check(dc, arg);

        tcg_gen_brcondi_i32(TCG_COND_NE, cpu_R[arg[1]], 0x80000000,
                            label1);
        tcg_gen_brcondi_i32(TCG_COND_NE, cpu_R[arg[2]], 0xffffffff,
                            label1);
        tcg_gen_movi_i32(cpu_R[arg[0]],
                         par[0] ? 0x80000000 : 0);
        tcg_gen_br(label2);
        gen_set_label(label1);
        if (par[0]) {
            tcg_gen_div_i32(cpu_R[arg[0]],
                            cpu_R[arg[1]], cpu_R[arg[2]]);
        } else {
            tcg_gen_rem_i32(cpu_R[arg[0]],
                            cpu_R[arg[1]], cpu_R[arg[2]]);
        }
        gen_set_label(label2);
    }
}

static void translate_quou(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        gen_zero_check(dc, arg);
        if (par[0]) {
            tcg_gen_divu_i32(cpu_R[arg[0]],
                             cpu_R[arg[1]], cpu_R[arg[2]]);
        } else {
            tcg_gen_remu_i32(cpu_R[arg[0]],
                             cpu_R[arg[1]], cpu_R[arg[2]]);
        }
    }
}

static void translate_rer(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        gen_helper_rer(cpu_R[arg[0]], cpu_env, cpu_R[arg[1]]);
    }
}

static void translate_ret(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    gen_jump(dc, cpu_R[0]);
}

static void translate_retw(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    TCGv_i32 tmp = tcg_const_i32(dc->pc);
    gen_helper_retw(tmp, cpu_env, tmp);
    gen_jump(dc, tmp);
    tcg_temp_free(tmp);
}

static void translate_rfde(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        gen_jump(dc, cpu_SR[dc->config->ndepc ? DEPC : EPC1]);
    }
}

static void translate_rfe(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        tcg_gen_andi_i32(cpu_SR[PS], cpu_SR[PS], ~PS_EXCM);
        gen_check_interrupts(dc);
        gen_jump(dc, cpu_SR[EPC1]);
    }
}

static void translate_rfi(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        tcg_gen_mov_i32(cpu_SR[PS], cpu_SR[EPS2 + arg[0] - 2]);
        gen_check_interrupts(dc);
        gen_jump(dc, cpu_SR[EPC1 + arg[0] - 1]);
    }
}

static void translate_rfw(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        TCGv_i32 tmp = tcg_const_i32(1);

        tcg_gen_andi_i32(cpu_SR[PS], cpu_SR[PS], ~PS_EXCM);
        tcg_gen_shl_i32(tmp, tmp, cpu_SR[WINDOW_BASE]);

        if (par[0]) {
            tcg_gen_andc_i32(cpu_SR[WINDOW_START],
                             cpu_SR[WINDOW_START], tmp);
        } else {
            tcg_gen_or_i32(cpu_SR[WINDOW_START],
                           cpu_SR[WINDOW_START], tmp);
        }

        gen_helper_restore_owb(cpu_env);
        gen_check_interrupts(dc);
        gen_jump(dc, cpu_SR[EPC1]);

        tcg_temp_free(tmp);
    }
}

static void translate_rotw(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        TCGv_i32 tmp = tcg_const_i32(arg[0]);
        gen_helper_rotw(cpu_env, tmp);
        tcg_temp_free(tmp);
        /* This can change tb->flags, so exit tb */
        gen_jumpi_check_loop_end(dc, -1);
    }
}

static void translate_rsil(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check1(dc, arg[0])) {
        tcg_gen_mov_i32(cpu_R[arg[0]], cpu_SR[PS]);
        tcg_gen_andi_i32(cpu_SR[PS], cpu_SR[PS], ~PS_INTLEVEL);
        tcg_gen_ori_i32(cpu_SR[PS], cpu_SR[PS], arg[1]);
        gen_check_interrupts(dc);
        gen_jumpi_check_loop_end(dc, 0);
    }
}

static void translate_rsr(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if ((par[0] < 64 || gen_check_privilege(dc)) &&
       gen_window_check1(dc, arg[0])) {
        if (gen_rsr(dc, cpu_R[arg[0]], par[0])) {
            gen_jumpi_check_loop_end(dc, 0);
        }
    }
}

static void translate_rtlb(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    static void (* const helper[])(TCGv_i32 r, TCGv_env env, TCGv_i32 a1,
                                   TCGv_i32 a2) = {
        gen_helper_rtlb0,
        gen_helper_rtlb1,
    };

    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 dtlb = tcg_const_i32(par[0]);

        helper[par[1]](cpu_R[arg[0]], cpu_env, cpu_R[arg[1]], dtlb);
        tcg_temp_free(dtlb);
    }
}

static void translate_rur(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        if (uregnames[par[0]].name) {
            tcg_gen_mov_i32(cpu_R[arg[0]], cpu_UR[par[0]]);
        } else {
            qemu_log_mask(LOG_UNIMP, "RUR %d not implemented, ", par[0]);
        }
    }
}

static void translate_s32c1i(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        TCGLabel *label = gen_new_label();
        TCGv_i32 tmp = tcg_temp_local_new_i32();
        TCGv_i32 addr = tcg_temp_local_new_i32();
        TCGv_i32 tpc;

        tcg_gen_mov_i32(tmp, cpu_R[arg[0]]);
        tcg_gen_addi_i32(addr, cpu_R[arg[1]], arg[2]);
        gen_load_store_alignment(dc, 2, addr, true);

        tpc = tcg_const_i32(dc->pc);
        gen_helper_check_atomctl(cpu_env, tpc, addr);
        tcg_gen_qemu_ld32u(cpu_R[arg[0]], addr, dc->cring);
        tcg_gen_brcond_i32(TCG_COND_NE, cpu_R[arg[0]],
                           cpu_SR[SCOMPARE1], label);

        tcg_gen_qemu_st32(tmp, addr, dc->cring);

        gen_set_label(label);
        tcg_temp_free(tpc);
        tcg_temp_free(addr);
        tcg_temp_free(tmp);
    }
}

static void translate_s32e(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_addi_i32(addr, cpu_R[arg[1]], arg[2]);
        gen_load_store_alignment(dc, 2, addr, false);
        tcg_gen_qemu_st_tl(cpu_R[arg[0]], addr, dc->ring, MO_TEUL);
        tcg_temp_free(addr);
    }
}

static void translate_sext(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        int shift = 31 - arg[2];

        if (shift == 24) {
            tcg_gen_ext8s_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
        } else if (shift == 16) {
            tcg_gen_ext16s_i32(cpu_R[arg[0]], cpu_R[arg[1]]);
        } else {
            TCGv_i32 tmp = tcg_temp_new_i32();
            tcg_gen_shli_i32(tmp, cpu_R[arg[1]], shift);
            tcg_gen_sari_i32(cpu_R[arg[0]], tmp, shift);
            tcg_temp_free(tmp);
        }
    }
}

static void translate_simcall(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (semihosting_enabled()) {
        if (gen_check_privilege(dc)) {
            gen_helper_simcall(cpu_env);
        }
    } else {
        qemu_log_mask(LOG_GUEST_ERROR, "SIMCALL but semihosting is disabled\n");
        gen_exception_cause(dc, ILLEGAL_INSTRUCTION_CAUSE);
    }
}

/*
 * Note: 64 bit ops are used here solely because SAR values
 * have range 0..63
 */
#define gen_shift_reg(cmd, reg) do { \
                    TCGv_i64 tmp = tcg_temp_new_i64(); \
                    tcg_gen_extu_i32_i64(tmp, reg); \
                    tcg_gen_##cmd##_i64(v, v, tmp); \
                    tcg_gen_extrl_i64_i32(cpu_R[arg[0]], v); \
                    tcg_temp_free_i64(v); \
                    tcg_temp_free_i64(tmp); \
                } while (0)

#define gen_shift(cmd) gen_shift_reg(cmd, cpu_SR[SAR])

static void translate_sll(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        if (dc->sar_m32_5bit) {
            tcg_gen_shl_i32(cpu_R[arg[0]], cpu_R[arg[1]], dc->sar_m32);
        } else {
            TCGv_i64 v = tcg_temp_new_i64();
            TCGv_i32 s = tcg_const_i32(32);
            tcg_gen_sub_i32(s, s, cpu_SR[SAR]);
            tcg_gen_andi_i32(s, s, 0x3f);
            tcg_gen_extu_i32_i64(v, cpu_R[arg[1]]);
            gen_shift_reg(shl, s);
            tcg_temp_free(s);
        }
    }
}

static void translate_slli(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        if (arg[2] == 32) {
            qemu_log_mask(LOG_GUEST_ERROR, "slli a%d, a%d, 32 is undefined",
                          arg[0], arg[1]);
        }
        tcg_gen_shli_i32(cpu_R[arg[0]], cpu_R[arg[1]], arg[2] & 0x1f);
    }
}

static void translate_sra(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        if (dc->sar_m32_5bit) {
            tcg_gen_sar_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_SR[SAR]);
        } else {
            TCGv_i64 v = tcg_temp_new_i64();
            tcg_gen_ext_i32_i64(v, cpu_R[arg[1]]);
            gen_shift(sar);
        }
    }
}

static void translate_srai(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_sari_i32(cpu_R[arg[0]], cpu_R[arg[1]], arg[2]);
    }
}

static void translate_src(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i64 v = tcg_temp_new_i64();
        tcg_gen_concat_i32_i64(v, cpu_R[arg[2]], cpu_R[arg[1]]);
        gen_shift(shr);
    }
}

static void translate_srl(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        if (dc->sar_m32_5bit) {
            tcg_gen_shr_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_SR[SAR]);
        } else {
            TCGv_i64 v = tcg_temp_new_i64();
            tcg_gen_extu_i32_i64(v, cpu_R[arg[1]]);
            gen_shift(shr);
        }
    }
}

#undef gen_shift
#undef gen_shift_reg

static void translate_srli(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[0], arg[1])) {
        tcg_gen_shri_i32(cpu_R[arg[0]], cpu_R[arg[1]], arg[2]);
    }
}

static void translate_ssa8b(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_shli_i32(tmp, cpu_R[arg[0]], 3);
        gen_left_shift_sar(dc, tmp);
        tcg_temp_free(tmp);
    }
}

static void translate_ssa8l(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_shli_i32(tmp, cpu_R[arg[0]], 3);
        gen_right_shift_sar(dc, tmp);
        tcg_temp_free(tmp);
    }
}

static void translate_ssai(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    TCGv_i32 tmp = tcg_const_i32(arg[0]);
    gen_right_shift_sar(dc, tmp);
    tcg_temp_free(tmp);
}

static void translate_ssl(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        gen_left_shift_sar(dc, cpu_R[arg[0]]);
    }
}

static void translate_ssr(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        gen_right_shift_sar(dc, cpu_R[arg[0]]);
    }
}

static void translate_sub(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_sub_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_subx(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        tcg_gen_shli_i32(tmp, cpu_R[arg[1]], par[0]);
        tcg_gen_sub_i32(cpu_R[arg[0]], tmp, cpu_R[arg[2]]);
        tcg_temp_free(tmp);
    }
}

static void translate_syscall(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    gen_exception_cause(dc, SYSCALL_CAUSE);
}

static void translate_waiti(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc)) {
        gen_waiti(dc, arg[0]);
    }
}

static void translate_wtlb(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        TCGv_i32 dtlb = tcg_const_i32(par[0]);

        gen_helper_wtlb(cpu_env, cpu_R[arg[0]], cpu_R[arg[1]], dtlb);
        /* This could change memory mapping, so exit tb */
        gen_jumpi_check_loop_end(dc, -1);
        tcg_temp_free(dtlb);
    }
}

static void translate_wer(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_privilege(dc) &&
        gen_window_check2(dc, arg[0], arg[1])) {
        gen_helper_wer(cpu_env, cpu_R[arg[0]], cpu_R[arg[1]]);
    }
}

static void translate_wsr(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if ((par[0] < 64 || gen_check_privilege(dc)) &&
       gen_window_check1(dc, arg[0])) {
        gen_wsr(dc, par[0], cpu_R[arg[0]]);
    }
}

static void translate_wur(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0])) {
        if (uregnames[par[0]].name) {
            gen_wur(par[0], cpu_R[arg[0]]);
        } else {
            qemu_log_mask(LOG_UNIMP, "WUR %d not implemented, ", par[0]);
        }
    }
}

static void translate_xor(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check3(dc, arg[0], arg[1], arg[2])) {
        tcg_gen_xor_i32(cpu_R[arg[0]], cpu_R[arg[1]], cpu_R[arg[2]]);
    }
}

static void translate_xsr(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if ((par[0] < 64 || gen_check_privilege(dc)) &&
       gen_window_check1(dc, arg[0])) {
        TCGv_i32 tmp = tcg_temp_new_i32();
        bool rsr_end, wsr_end;

        tcg_gen_mov_i32(tmp, cpu_R[arg[0]]);
        rsr_end = gen_rsr(dc, cpu_R[arg[0]], par[0]);
        wsr_end = gen_wsr(dc, par[0], tmp);
        tcg_temp_free(tmp);
        if (rsr_end && !wsr_end) {
            gen_jumpi_check_loop_end(dc, 0);
        }
    }
}

static const XtensaOpcodeMap core_map[] = {
    { "abs", translate_abs },
    { "add", translate_add },
    { "add.n", translate_add },
    { "addi", translate_addi },
    { "addi.n", translate_addi },
    { "addmi", translate_addi },
    { "addx2", translate_addx, (uint32_t[]){1} },
    { "addx4", translate_addx, (uint32_t[]){2} },
    { "addx8", translate_addx, (uint32_t[]){3} },
    { "all4", translate_all, (uint32_t[]){true, 4} },
    { "all8", translate_all, (uint32_t[]){true, 8} },
    { "and", translate_and },
    { "andb", translate_boolean, (uint32_t[]){BOOLEAN_AND} },
    { "andbc", translate_boolean, (uint32_t[]){BOOLEAN_ANDC} },
    { "any4", translate_all, (uint32_t[]){false, 4} },
    { "any8", translate_all, (uint32_t[]){false, 8} },
    { "ball", translate_ball, (uint32_t[]){TCG_COND_EQ} },
    { "bany", translate_bany, (uint32_t[]){TCG_COND_NE} },
    { "bbc", translate_bb, (uint32_t[]){TCG_COND_EQ} },
    { "bbci", translate_bbi, (uint32_t[]){TCG_COND_EQ} },
    { "bbs", translate_bb, (uint32_t[]){TCG_COND_NE} },
    { "bbsi", translate_bbi, (uint32_t[]){TCG_COND_NE} },
    { "beq", translate_b, (uint32_t[]){TCG_COND_EQ} },
    { "beqi", translate_bi, (uint32_t[]){TCG_COND_EQ} },
    { "beqz", translate_bz, (uint32_t[]){TCG_COND_EQ} },
    { "beqz.n", translate_bz, (uint32_t[]){TCG_COND_EQ} },
    { "bf", translate_bp, (uint32_t[]){TCG_COND_EQ} },
    { "bge", translate_b, (uint32_t[]){TCG_COND_GE} },
    { "bgei", translate_bi, (uint32_t[]){TCG_COND_GE} },
    { "bgeu", translate_b, (uint32_t[]){TCG_COND_GEU} },
    { "bgeui", translate_bi, (uint32_t[]){TCG_COND_GEU} },
    { "bgez", translate_bz, (uint32_t[]){TCG_COND_GE} },
    { "blt", translate_b, (uint32_t[]){TCG_COND_LT} },
    { "blti", translate_bi, (uint32_t[]){TCG_COND_LT} },
    { "bltu", translate_b, (uint32_t[]){TCG_COND_LTU} },
    { "bltui", translate_bi, (uint32_t[]){TCG_COND_LTU} },
    { "bltz", translate_bz, (uint32_t[]){TCG_COND_LT} },
    { "bnall", translate_ball, (uint32_t[]){TCG_COND_NE} },
    { "bne", translate_b, (uint32_t[]){TCG_COND_NE} },
    { "bnei", translate_bi, (uint32_t[]){TCG_COND_NE} },
    { "bnez", translate_bz, (uint32_t[]){TCG_COND_NE} },
    { "bnez.n", translate_bz, (uint32_t[]){TCG_COND_NE} },
    { "bnone", translate_bany, (uint32_t[]){TCG_COND_EQ} },
    { "break", translate_break, (uint32_t[]){DEBUGCAUSE_BI} },
    { "break.n", translate_break, (uint32_t[]){DEBUGCAUSE_BN} },
    { "bt", translate_bp, (uint32_t[]){TCG_COND_NE} },
    { "call0", translate_call0 },
    { "call12", translate_callw, (uint32_t[]){3} },
    { "call4", translate_callw, (uint32_t[]){1} },
    { "call8", translate_callw, (uint32_t[]){2} },
    { "callx0", translate_callx0 },
    { "callx12", translate_callxw, (uint32_t[]){3} },
    { "callx4", translate_callxw, (uint32_t[]){1} },
    { "callx8", translate_callxw, (uint32_t[]){2} },
    { "clamps", translate_clamps },
    { "depbits", translate_depbits },
    { "dhi", translate_dcache, (uint32_t[]){true, true} },
    { "dhu", translate_dcache, (uint32_t[]){true, true} },
    { "dhwb", translate_dcache, (uint32_t[]){false, true} },
    { "dhwbi", translate_dcache, (uint32_t[]){false, true} },
    { "dii", translate_dcache, (uint32_t[]){true, false} },
    { "diu", translate_dcache, (uint32_t[]){true, false} },
    { "diwb", translate_dcache, (uint32_t[]){true, false} },
    { "diwbi", translate_dcache, (uint32_t[]){true, false} },
    { "dpfl", translate_dcache, (uint32_t[]){true, true} },
    { "dpfr", translate_dcache, (uint32_t[]){false, false} },
    { "dpfro", translate_dcache, (uint32_t[]){false, false} },
    { "dpfw", translate_dcache, (uint32_t[]){false, false} },
    { "dpfwo", translate_dcache, (uint32_t[]){false, false} },
    { "dsync", translate_nop },
    { "entry", translate_entry },
    { "esync", translate_nop },
    { "excw", translate_nop },
    { "extui", translate_extui },
    { "extw", translate_nop },
    { "idtlb", translate_itlb, (uint32_t[]){true} },
    { "ihi", translate_icache, (uint32_t[]){false, true} },
    { "ihu", translate_icache, (uint32_t[]){true, true} },
    { "iii", translate_icache, (uint32_t[]){true, false} },
    { "iitlb", translate_itlb, (uint32_t[]){false} },
    { "iiu", translate_icache, (uint32_t[]){true, false} },
    { "ill", translate_ill },
    { "ill.n", translate_ill },
    { "ipf", translate_icache, (uint32_t[]){false, false} },
    { "ipfl", translate_icache, (uint32_t[]){true, true} },
    { "isync", translate_nop },
    { "j", translate_j },
    { "jx", translate_jx },
    { "l16si", translate_ldst, (uint32_t[]){MO_TESW, false, false} },
    { "l16ui", translate_ldst, (uint32_t[]){MO_TEUW, false, false} },
    { "l32ai", translate_ldst, (uint32_t[]){MO_TEUL, true, false} },
    { "l32e", translate_l32e },
    { "l32i", translate_ldst, (uint32_t[]){MO_TEUL, false, false} },
    { "l32i.n", translate_ldst, (uint32_t[]){MO_TEUL, false, false} },
    { "l32r", translate_l32r },
    { "l8ui", translate_ldst, (uint32_t[]){MO_UB, false, false} },
    { "lddec", translate_mac16, (uint32_t[]){MAC16_NONE, 0, 0, -4} },
    { "ldinc", translate_mac16, (uint32_t[]){MAC16_NONE, 0, 0, 4} },
    { "loop", translate_loop, (uint32_t[]){TCG_COND_NEVER} },
    { "loopgtz", translate_loop, (uint32_t[]){TCG_COND_GT} },
    { "loopnez", translate_loop, (uint32_t[]){TCG_COND_NE} },
    { "max", translate_minmax, (uint32_t[]){TCG_COND_GE} },
    { "maxu", translate_minmax, (uint32_t[]){TCG_COND_GEU} },
    { "memw", translate_nop },
    { "min", translate_minmax, (uint32_t[]){TCG_COND_LT} },
    { "minu", translate_minmax, (uint32_t[]){TCG_COND_LTU} },
    { "mov", translate_mov },
    { "mov.n", translate_mov },
    { "moveqz", translate_movcond, (uint32_t[]){TCG_COND_EQ} },
    { "movf", translate_movp, (uint32_t[]){TCG_COND_EQ} },
    { "movgez", translate_movcond, (uint32_t[]){TCG_COND_GE} },
    { "movi", translate_movi },
    { "movi.n", translate_movi },
    { "movltz", translate_movcond, (uint32_t[]){TCG_COND_LT} },
    { "movnez", translate_movcond, (uint32_t[]){TCG_COND_NE} },
    { "movsp", translate_movsp },
    { "movt", translate_movp, (uint32_t[]){TCG_COND_NE} },
    { "mul.aa.hh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AA, MAC16_HH, 0} },
    { "mul.aa.hl", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AA, MAC16_HL, 0} },
    { "mul.aa.lh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AA, MAC16_LH, 0} },
    { "mul.aa.ll", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AA, MAC16_LL, 0} },
    { "mul.ad.hh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AD, MAC16_HH, 0} },
    { "mul.ad.hl", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AD, MAC16_HL, 0} },
    { "mul.ad.lh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AD, MAC16_LH, 0} },
    { "mul.ad.ll", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_AD, MAC16_LL, 0} },
    { "mul.da.hh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DA, MAC16_HH, 0} },
    { "mul.da.hl", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DA, MAC16_HL, 0} },
    { "mul.da.lh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DA, MAC16_LH, 0} },
    { "mul.da.ll", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DA, MAC16_LL, 0} },
    { "mul.dd.hh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DD, MAC16_HH, 0} },
    { "mul.dd.hl", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DD, MAC16_HL, 0} },
    { "mul.dd.lh", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DD, MAC16_LH, 0} },
    { "mul.dd.ll", translate_mac16, (uint32_t[]){MAC16_MUL, MAC16_DD, MAC16_LL, 0} },
    { "mul16s", translate_mul16, (uint32_t[]){true} },
    { "mul16u", translate_mul16, (uint32_t[]){false} },
    { "mula.aa.hh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AA, MAC16_HH, 0} },
    { "mula.aa.hl", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AA, MAC16_HL, 0} },
    { "mula.aa.lh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AA, MAC16_LH, 0} },
    { "mula.aa.ll", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AA, MAC16_LL, 0} },
    { "mula.ad.hh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AD, MAC16_HH, 0} },
    { "mula.ad.hl", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AD, MAC16_HL, 0} },
    { "mula.ad.lh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AD, MAC16_LH, 0} },
    { "mula.ad.ll", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_AD, MAC16_LL, 0} },
    { "mula.da.hh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HH, 0} },
    { "mula.da.hh.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HH, -4} },
    { "mula.da.hh.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HH, 4} },
    { "mula.da.hl", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HL, 0} },
    { "mula.da.hl.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HL, -4} },
    { "mula.da.hl.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_HL, 4} },
    { "mula.da.lh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LH, 0} },
    { "mula.da.lh.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LH, -4} },
    { "mula.da.lh.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LH, 4} },
    { "mula.da.ll", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LL, 0} },
    { "mula.da.ll.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LL, -4} },
    { "mula.da.ll.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DA, MAC16_LL, 4} },
    { "mula.dd.hh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HH, 0} },
    { "mula.dd.hh.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HH, -4} },
    { "mula.dd.hh.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HH, 4} },
    { "mula.dd.hl", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HL, 0} },
    { "mula.dd.hl.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HL, -4} },
    { "mula.dd.hl.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_HL, 4} },
    { "mula.dd.lh", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LH, 0} },
    { "mula.dd.lh.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LH, -4} },
    { "mula.dd.lh.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LH, 4} },
    { "mula.dd.ll", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LL, 0} },
    { "mula.dd.ll.lddec", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LL, -4} },
    { "mula.dd.ll.ldinc", translate_mac16, (uint32_t[]){MAC16_MULA, MAC16_DD, MAC16_LL, 4} },
    { "mull", translate_mull },
    { "muls.aa.hh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AA, MAC16_HH, 0} },
    { "muls.aa.hl", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AA, MAC16_HL, 0} },
    { "muls.aa.lh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AA, MAC16_LH, 0} },
    { "muls.aa.ll", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AA, MAC16_LL, 0} },
    { "muls.ad.hh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AD, MAC16_HH, 0} },
    { "muls.ad.hl", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AD, MAC16_HL, 0} },
    { "muls.ad.lh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AD, MAC16_LH, 0} },
    { "muls.ad.ll", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_AD, MAC16_LL, 0} },
    { "muls.da.hh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DA, MAC16_HH, 0} },
    { "muls.da.hl", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DA, MAC16_HL, 0} },
    { "muls.da.lh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DA, MAC16_LH, 0} },
    { "muls.da.ll", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DA, MAC16_LL, 0} },
    { "muls.dd.hh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DD, MAC16_HH, 0} },
    { "muls.dd.hl", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DD, MAC16_HL, 0} },
    { "muls.dd.lh", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DD, MAC16_LH, 0} },
    { "muls.dd.ll", translate_mac16, (uint32_t[]){MAC16_MULS, MAC16_DD, MAC16_LL, 0} },
    { "mulsh", translate_mulh, (uint32_t[]){true} },
    { "muluh", translate_mulh, (uint32_t[]){false} },
    { "neg", translate_neg },
    { "nop", translate_nop },
    { "nop.n", translate_nop },
    { "nsa", translate_nsa },
    { "nsau", translate_nsau },
    { "or", translate_or },
    { "orb", translate_boolean, (uint32_t[]){BOOLEAN_OR} },
    { "orbc", translate_boolean, (uint32_t[]){BOOLEAN_ORC} },
    { "pdtlb", translate_ptlb, (uint32_t[]){true} },
    { "pitlb", translate_ptlb, (uint32_t[]){false} },
    { "quos", translate_quos, (uint32_t[]){true} },
    { "quou", translate_quou, (uint32_t[]){true} },
    { "rdtlb0", translate_rtlb, (uint32_t[]){true, 0} },
    { "rdtlb1", translate_rtlb, (uint32_t[]){true, 1} },
    { "rems", translate_quos, (uint32_t[]){false} },
    { "remu", translate_quou, (uint32_t[]){false} },
    { "rer", translate_rer },
    { "ret", translate_ret },
    { "ret.n", translate_ret },
    { "retw", translate_retw },
    { "retw.n", translate_retw },
    { "rfde", translate_rfde },
    { "rfe", translate_rfe },
    { "rfi", translate_rfi },
    { "rfwo", translate_rfw, (uint32_t[]){true} },
    { "rfwu", translate_rfw, (uint32_t[]){false} },
    { "ritlb0", translate_rtlb, (uint32_t[]){false, 0} },
    { "ritlb1", translate_rtlb, (uint32_t[]){false, 1} },
    { "rotw", translate_rotw },
    { "rsil", translate_rsil },
    { "rsr.176", translate_rsr, (uint32_t[]){176} },
    { "rsr.208", translate_rsr, (uint32_t[]){208} },
    { "rsr.acchi", translate_rsr, (uint32_t[]){ACCHI} },
    { "rsr.acclo", translate_rsr, (uint32_t[]){ACCLO} },
    { "rsr.atomctl", translate_rsr, (uint32_t[]){ATOMCTL} },
    { "rsr.br", translate_rsr, (uint32_t[]){BR} },
    { "rsr.cacheattr", translate_rsr, (uint32_t[]){CACHEATTR} },
    { "rsr.ccompare0", translate_rsr, (uint32_t[]){CCOMPARE} },
    { "rsr.ccompare1", translate_rsr, (uint32_t[]){CCOMPARE + 1} },
    { "rsr.ccompare2", translate_rsr, (uint32_t[]){CCOMPARE + 2} },
    { "rsr.ccount", translate_rsr, (uint32_t[]){CCOUNT} },
    { "rsr.configid0", translate_rsr, (uint32_t[]){CONFIGID0} },
    { "rsr.configid1", translate_rsr, (uint32_t[]){CONFIGID1} },
    { "rsr.cpenable", translate_rsr, (uint32_t[]){CPENABLE} },
    { "rsr.dbreaka0", translate_rsr, (uint32_t[]){DBREAKA} },
    { "rsr.dbreaka1", translate_rsr, (uint32_t[]){DBREAKA + 1} },
    { "rsr.dbreakc0", translate_rsr, (uint32_t[]){DBREAKC} },
    { "rsr.dbreakc1", translate_rsr, (uint32_t[]){DBREAKC + 1} },
    { "rsr.debugcause", translate_rsr, (uint32_t[]){DEBUGCAUSE} },
    { "rsr.depc", translate_rsr, (uint32_t[]){DEPC} },
    { "rsr.dtlbcfg", translate_rsr, (uint32_t[]){DTLBCFG} },
    { "rsr.epc1", translate_rsr, (uint32_t[]){EPC1} },
    { "rsr.epc2", translate_rsr, (uint32_t[]){EPC1 + 1} },
    { "rsr.epc3", translate_rsr, (uint32_t[]){EPC1 + 2} },
    { "rsr.epc4", translate_rsr, (uint32_t[]){EPC1 + 3} },
    { "rsr.epc5", translate_rsr, (uint32_t[]){EPC1 + 4} },
    { "rsr.epc6", translate_rsr, (uint32_t[]){EPC1 + 5} },
    { "rsr.epc7", translate_rsr, (uint32_t[]){EPC1 + 6} },
    { "rsr.eps2", translate_rsr, (uint32_t[]){EPS2} },
    { "rsr.eps3", translate_rsr, (uint32_t[]){EPS2 + 1} },
    { "rsr.eps4", translate_rsr, (uint32_t[]){EPS2 + 2} },
    { "rsr.eps5", translate_rsr, (uint32_t[]){EPS2 + 3} },
    { "rsr.eps6", translate_rsr, (uint32_t[]){EPS2 + 4} },
    { "rsr.eps7", translate_rsr, (uint32_t[]){EPS2 + 5} },
    { "rsr.exccause", translate_rsr, (uint32_t[]){EXCCAUSE} },
    { "rsr.excsave1", translate_rsr, (uint32_t[]){EXCSAVE1} },
    { "rsr.excsave2", translate_rsr, (uint32_t[]){EXCSAVE1 + 1} },
    { "rsr.excsave3", translate_rsr, (uint32_t[]){EXCSAVE1 + 2} },
    { "rsr.excsave4", translate_rsr, (uint32_t[]){EXCSAVE1 + 3} },
    { "rsr.excsave5", translate_rsr, (uint32_t[]){EXCSAVE1 + 4} },
    { "rsr.excsave6", translate_rsr, (uint32_t[]){EXCSAVE1 + 5} },
    { "rsr.excsave7", translate_rsr, (uint32_t[]){EXCSAVE1 + 6} },
    { "rsr.excvaddr", translate_rsr, (uint32_t[]){EXCVADDR} },
    { "rsr.ibreaka0", translate_rsr, (uint32_t[]){IBREAKA} },
    { "rsr.ibreaka1", translate_rsr, (uint32_t[]){IBREAKA + 1} },
    { "rsr.ibreakenable", translate_rsr, (uint32_t[]){IBREAKENABLE} },
    { "rsr.icount", translate_rsr, (uint32_t[]){ICOUNT} },
    { "rsr.icountlevel", translate_rsr, (uint32_t[]){ICOUNTLEVEL} },
    { "rsr.intclear", translate_rsr, (uint32_t[]){INTCLEAR} },
    { "rsr.intenable", translate_rsr, (uint32_t[]){INTENABLE} },
    { "rsr.interrupt", translate_rsr, (uint32_t[]){INTSET} },
    { "rsr.intset", translate_rsr, (uint32_t[]){INTSET} },
    { "rsr.itlbcfg", translate_rsr, (uint32_t[]){ITLBCFG} },
    { "rsr.lbeg", translate_rsr, (uint32_t[]){LBEG} },
    { "rsr.lcount", translate_rsr, (uint32_t[]){LCOUNT} },
    { "rsr.lend", translate_rsr, (uint32_t[]){LEND} },
    { "rsr.litbase", translate_rsr, (uint32_t[]){LITBASE} },
    { "rsr.m0", translate_rsr, (uint32_t[]){MR} },
    { "rsr.m1", translate_rsr, (uint32_t[]){MR + 1} },
    { "rsr.m2", translate_rsr, (uint32_t[]){MR + 2} },
    { "rsr.m3", translate_rsr, (uint32_t[]){MR + 3} },
    { "rsr.memctl", translate_rsr, (uint32_t[]){MEMCTL} },
    { "rsr.misc0", translate_rsr, (uint32_t[]){MISC} },
    { "rsr.misc1", translate_rsr, (uint32_t[]){MISC + 1} },
    { "rsr.misc2", translate_rsr, (uint32_t[]){MISC + 2} },
    { "rsr.misc3", translate_rsr, (uint32_t[]){MISC + 3} },
    { "rsr.prid", translate_rsr, (uint32_t[]){PRID} },
    { "rsr.ps", translate_rsr, (uint32_t[]){PS} },
    { "rsr.ptevaddr", translate_rsr, (uint32_t[]){PTEVADDR} },
    { "rsr.rasid", translate_rsr, (uint32_t[]){RASID} },
    { "rsr.sar", translate_rsr, (uint32_t[]){SAR} },
    { "rsr.scompare1", translate_rsr, (uint32_t[]){SCOMPARE1} },
    { "rsr.vecbase", translate_rsr, (uint32_t[]){VECBASE} },
    { "rsr.windowbase", translate_rsr, (uint32_t[]){WINDOW_BASE} },
    { "rsr.windowstart", translate_rsr, (uint32_t[]){WINDOW_START} },
    { "rsync", translate_nop },
    { "rur.fcr", translate_rur, (uint32_t[]){FCR} },
    { "rur.fsr", translate_rur, (uint32_t[]){FSR} },
    { "rur.threadptr", translate_rur, (uint32_t[]){THREADPTR} },
    { "s16i", translate_ldst, (uint32_t[]){MO_TEUW, false, true} },
    { "s32c1i", translate_s32c1i },
    { "s32e", translate_s32e },
    { "s32i", translate_ldst, (uint32_t[]){MO_TEUL, false, true} },
    { "s32i.n", translate_ldst, (uint32_t[]){MO_TEUL, false, true} },
    { "s32nb", translate_ldst, (uint32_t[]){MO_TEUL, false, true} },
    { "s32ri", translate_ldst, (uint32_t[]){MO_TEUL, true, true} },
    { "s8i", translate_ldst, (uint32_t[]){MO_UB, false, true} },
    { "sext", translate_sext },
    { "simcall", translate_simcall },
    { "sll", translate_sll },
    { "slli", translate_slli },
    { "sra", translate_sra },
    { "srai", translate_srai },
    { "src", translate_src },
    { "srl", translate_srl },
    { "srli", translate_srli },
    { "ssa8b", translate_ssa8b },
    { "ssa8l", translate_ssa8l },
    { "ssai", translate_ssai },
    { "ssl", translate_ssl },
    { "ssr", translate_ssr },
    { "sub", translate_sub },
    { "subx2", translate_subx, (uint32_t[]){1} },
    { "subx4", translate_subx, (uint32_t[]){2} },
    { "subx8", translate_subx, (uint32_t[]){3} },
    { "syscall", translate_syscall },
    { "umul.aa.hh", translate_mac16, (uint32_t[]){MAC16_UMUL, MAC16_AA, MAC16_HH, 0} },
    { "umul.aa.hl", translate_mac16, (uint32_t[]){MAC16_UMUL, MAC16_AA, MAC16_HL, 0} },
    { "umul.aa.lh", translate_mac16, (uint32_t[]){MAC16_UMUL, MAC16_AA, MAC16_LH, 0} },
    { "umul.aa.ll", translate_mac16, (uint32_t[]){MAC16_UMUL, MAC16_AA, MAC16_LL, 0} },
    { "waiti", translate_waiti },
    { "wdtlb", translate_wtlb, (uint32_t[]){true} },
    { "wer", translate_wer },
    { "witlb", translate_wtlb, (uint32_t[]){false} },
    { "wsr.176", translate_wsr, (uint32_t[]){176} },
    { "wsr.208", translate_wsr, (uint32_t[]){208} },
    { "wsr.acchi", translate_wsr, (uint32_t[]){ACCHI} },
    { "wsr.acclo", translate_wsr, (uint32_t[]){ACCLO} },
    { "wsr.atomctl", translate_wsr, (uint32_t[]){ATOMCTL} },
    { "wsr.br", translate_wsr, (uint32_t[]){BR} },
    { "wsr.cacheattr", translate_wsr, (uint32_t[]){CACHEATTR} },
    { "wsr.ccompare0", translate_wsr, (uint32_t[]){CCOMPARE} },
    { "wsr.ccompare1", translate_wsr, (uint32_t[]){CCOMPARE + 1} },
    { "wsr.ccompare2", translate_wsr, (uint32_t[]){CCOMPARE + 2} },
    { "wsr.ccount", translate_wsr, (uint32_t[]){CCOUNT} },
    { "wsr.configid0", translate_wsr, (uint32_t[]){CONFIGID0} },
    { "wsr.configid1", translate_wsr, (uint32_t[]){CONFIGID1} },
    { "wsr.cpenable", translate_wsr, (uint32_t[]){CPENABLE} },
    { "wsr.dbreaka0", translate_wsr, (uint32_t[]){DBREAKA} },
    { "wsr.dbreaka1", translate_wsr, (uint32_t[]){DBREAKA + 1} },
    { "wsr.dbreakc0", translate_wsr, (uint32_t[]){DBREAKC} },
    { "wsr.dbreakc1", translate_wsr, (uint32_t[]){DBREAKC + 1} },
    { "wsr.debugcause", translate_wsr, (uint32_t[]){DEBUGCAUSE} },
    { "wsr.depc", translate_wsr, (uint32_t[]){DEPC} },
    { "wsr.dtlbcfg", translate_wsr, (uint32_t[]){DTLBCFG} },
    { "wsr.epc1", translate_wsr, (uint32_t[]){EPC1} },
    { "wsr.epc2", translate_wsr, (uint32_t[]){EPC1 + 1} },
    { "wsr.epc3", translate_wsr, (uint32_t[]){EPC1 + 2} },
    { "wsr.epc4", translate_wsr, (uint32_t[]){EPC1 + 3} },
    { "wsr.epc5", translate_wsr, (uint32_t[]){EPC1 + 4} },
    { "wsr.epc6", translate_wsr, (uint32_t[]){EPC1 + 5} },
    { "wsr.epc7", translate_wsr, (uint32_t[]){EPC1 + 6} },
    { "wsr.eps2", translate_wsr, (uint32_t[]){EPS2} },
    { "wsr.eps3", translate_wsr, (uint32_t[]){EPS2 + 1} },
    { "wsr.eps4", translate_wsr, (uint32_t[]){EPS2 + 2} },
    { "wsr.eps5", translate_wsr, (uint32_t[]){EPS2 + 3} },
    { "wsr.eps6", translate_wsr, (uint32_t[]){EPS2 + 4} },
    { "wsr.eps7", translate_wsr, (uint32_t[]){EPS2 + 5} },
    { "wsr.exccause", translate_wsr, (uint32_t[]){EXCCAUSE} },
    { "wsr.excsave1", translate_wsr, (uint32_t[]){EXCSAVE1} },
    { "wsr.excsave2", translate_wsr, (uint32_t[]){EXCSAVE1 + 1} },
    { "wsr.excsave3", translate_wsr, (uint32_t[]){EXCSAVE1 + 2} },
    { "wsr.excsave4", translate_wsr, (uint32_t[]){EXCSAVE1 + 3} },
    { "wsr.excsave5", translate_wsr, (uint32_t[]){EXCSAVE1 + 4} },
    { "wsr.excsave6", translate_wsr, (uint32_t[]){EXCSAVE1 + 5} },
    { "wsr.excsave7", translate_wsr, (uint32_t[]){EXCSAVE1 + 6} },
    { "wsr.excvaddr", translate_wsr, (uint32_t[]){EXCVADDR} },
    { "wsr.ibreaka0", translate_wsr, (uint32_t[]){IBREAKA} },
    { "wsr.ibreaka1", translate_wsr, (uint32_t[]){IBREAKA + 1} },
    { "wsr.ibreakenable", translate_wsr, (uint32_t[]){IBREAKENABLE} },
    { "wsr.icount", translate_wsr, (uint32_t[]){ICOUNT} },
    { "wsr.icountlevel", translate_wsr, (uint32_t[]){ICOUNTLEVEL} },
    { "wsr.intclear", translate_wsr, (uint32_t[]){INTCLEAR} },
    { "wsr.intenable", translate_wsr, (uint32_t[]){INTENABLE} },
    { "wsr.interrupt", translate_wsr, (uint32_t[]){INTSET} },
    { "wsr.intset", translate_wsr, (uint32_t[]){INTSET} },
    { "wsr.itlbcfg", translate_wsr, (uint32_t[]){ITLBCFG} },
    { "wsr.lbeg", translate_wsr, (uint32_t[]){LBEG} },
    { "wsr.lcount", translate_wsr, (uint32_t[]){LCOUNT} },
    { "wsr.lend", translate_wsr, (uint32_t[]){LEND} },
    { "wsr.litbase", translate_wsr, (uint32_t[]){LITBASE} },
    { "wsr.m0", translate_wsr, (uint32_t[]){MR} },
    { "wsr.m1", translate_wsr, (uint32_t[]){MR + 1} },
    { "wsr.m2", translate_wsr, (uint32_t[]){MR + 2} },
    { "wsr.m3", translate_wsr, (uint32_t[]){MR + 3} },
    { "wsr.memctl", translate_wsr, (uint32_t[]){MEMCTL} },
    { "wsr.misc0", translate_wsr, (uint32_t[]){MISC} },
    { "wsr.misc1", translate_wsr, (uint32_t[]){MISC + 1} },
    { "wsr.misc2", translate_wsr, (uint32_t[]){MISC + 2} },
    { "wsr.misc3", translate_wsr, (uint32_t[]){MISC + 3} },
    { "wsr.prid", translate_wsr, (uint32_t[]){PRID} },
    { "wsr.ps", translate_wsr, (uint32_t[]){PS} },
    { "wsr.ptevaddr", translate_wsr, (uint32_t[]){PTEVADDR} },
    { "wsr.rasid", translate_wsr, (uint32_t[]){RASID} },
    { "wsr.sar", translate_wsr, (uint32_t[]){SAR} },
    { "wsr.scompare1", translate_wsr, (uint32_t[]){SCOMPARE1} },
    { "wsr.vecbase", translate_wsr, (uint32_t[]){VECBASE} },
    { "wsr.windowbase", translate_wsr, (uint32_t[]){WINDOW_BASE} },
    { "wsr.windowstart", translate_wsr, (uint32_t[]){WINDOW_START} },
    { "wur.fcr", translate_wur, (uint32_t[]){FCR} },
    { "wur.fsr", translate_wur, (uint32_t[]){FSR} },
    { "wur.threadptr", translate_wur, (uint32_t[]){THREADPTR} },
    { "xor", translate_xor },
    { "xorb", translate_boolean, (uint32_t[]){BOOLEAN_XOR} },
    { "xsr.176", translate_xsr, (uint32_t[]){176} },
    { "xsr.208", translate_xsr, (uint32_t[]){208} },
    { "xsr.acchi", translate_xsr, (uint32_t[]){ACCHI} },
    { "xsr.acclo", translate_xsr, (uint32_t[]){ACCLO} },
    { "xsr.atomctl", translate_xsr, (uint32_t[]){ATOMCTL} },
    { "xsr.br", translate_xsr, (uint32_t[]){BR} },
    { "xsr.cacheattr", translate_xsr, (uint32_t[]){CACHEATTR} },
    { "xsr.ccompare0", translate_xsr, (uint32_t[]){CCOMPARE} },
    { "xsr.ccompare1", translate_xsr, (uint32_t[]){CCOMPARE + 1} },
    { "xsr.ccompare2", translate_xsr, (uint32_t[]){CCOMPARE + 2} },
    { "xsr.ccount", translate_xsr, (uint32_t[]){CCOUNT} },
    { "xsr.configid0", translate_xsr, (uint32_t[]){CONFIGID0} },
    { "xsr.configid1", translate_xsr, (uint32_t[]){CONFIGID1} },
    { "xsr.cpenable", translate_xsr, (uint32_t[]){CPENABLE} },
    { "xsr.dbreaka0", translate_xsr, (uint32_t[]){DBREAKA} },
    { "xsr.dbreaka1", translate_xsr, (uint32_t[]){DBREAKA + 1} },
    { "xsr.dbreakc0", translate_xsr, (uint32_t[]){DBREAKC} },
    { "xsr.dbreakc1", translate_xsr, (uint32_t[]){DBREAKC + 1} },
    { "xsr.debugcause", translate_xsr, (uint32_t[]){DEBUGCAUSE} },
    { "xsr.depc", translate_xsr, (uint32_t[]){DEPC} },
    { "xsr.dtlbcfg", translate_xsr, (uint32_t[]){DTLBCFG} },
    { "xsr.epc1", translate_xsr, (uint32_t[]){EPC1} },
    { "xsr.epc2", translate_xsr, (uint32_t[]){EPC1 + 1} },
    { "xsr.epc3", translate_xsr, (uint32_t[]){EPC1 + 2} },
    { "xsr.epc4", translate_xsr, (uint32_t[]){EPC1 + 3} },
    { "xsr.epc5", translate_xsr, (uint32_t[]){EPC1 + 4} },
    { "xsr.epc6", translate_xsr, (uint32_t[]){EPC1 + 5} },
    { "xsr.epc7", translate_xsr, (uint32_t[]){EPC1 + 6} },
    { "xsr.eps2", translate_xsr, (uint32_t[]){EPS2} },
    { "xsr.eps3", translate_xsr, (uint32_t[]){EPS2 + 1} },
    { "xsr.eps4", translate_xsr, (uint32_t[]){EPS2 + 2} },
    { "xsr.eps5", translate_xsr, (uint32_t[]){EPS2 + 3} },
    { "xsr.eps6", translate_xsr, (uint32_t[]){EPS2 + 4} },
    { "xsr.eps7", translate_xsr, (uint32_t[]){EPS2 + 5} },
    { "xsr.exccause", translate_xsr, (uint32_t[]){EXCCAUSE} },
    { "xsr.excsave1", translate_xsr, (uint32_t[]){EXCSAVE1} },
    { "xsr.excsave2", translate_xsr, (uint32_t[]){EXCSAVE1 + 1} },
    { "xsr.excsave3", translate_xsr, (uint32_t[]){EXCSAVE1 + 2} },
    { "xsr.excsave4", translate_xsr, (uint32_t[]){EXCSAVE1 + 3} },
    { "xsr.excsave5", translate_xsr, (uint32_t[]){EXCSAVE1 + 4} },
    { "xsr.excsave6", translate_xsr, (uint32_t[]){EXCSAVE1 + 5} },
    { "xsr.excsave7", translate_xsr, (uint32_t[]){EXCSAVE1 + 6} },
    { "xsr.excvaddr", translate_xsr, (uint32_t[]){EXCVADDR} },
    { "xsr.ibreaka0", translate_xsr, (uint32_t[]){IBREAKA} },
    { "xsr.ibreaka1", translate_xsr, (uint32_t[]){IBREAKA + 1} },
    { "xsr.ibreakenable", translate_xsr, (uint32_t[]){IBREAKENABLE} },
    { "xsr.icount", translate_xsr, (uint32_t[]){ICOUNT} },
    { "xsr.icountlevel", translate_xsr, (uint32_t[]){ICOUNTLEVEL} },
    { "xsr.intclear", translate_xsr, (uint32_t[]){INTCLEAR} },
    { "xsr.intenable", translate_xsr, (uint32_t[]){INTENABLE} },
    { "xsr.interrupt", translate_xsr, (uint32_t[]){INTSET} },
    { "xsr.intset", translate_xsr, (uint32_t[]){INTSET} },
    { "xsr.itlbcfg", translate_xsr, (uint32_t[]){ITLBCFG} },
    { "xsr.lbeg", translate_xsr, (uint32_t[]){LBEG} },
    { "xsr.lcount", translate_xsr, (uint32_t[]){LCOUNT} },
    { "xsr.lend", translate_xsr, (uint32_t[]){LEND} },
    { "xsr.litbase", translate_xsr, (uint32_t[]){LITBASE} },
    { "xsr.m0", translate_xsr, (uint32_t[]){MR} },
    { "xsr.m1", translate_xsr, (uint32_t[]){MR + 1} },
    { "xsr.m2", translate_xsr, (uint32_t[]){MR + 2} },
    { "xsr.m3", translate_xsr, (uint32_t[]){MR + 3} },
    { "xsr.memctl", translate_xsr, (uint32_t[]){MEMCTL} },
    { "xsr.misc0", translate_xsr, (uint32_t[]){MISC} },
    { "xsr.misc1", translate_xsr, (uint32_t[]){MISC + 1} },
    { "xsr.misc2", translate_xsr, (uint32_t[]){MISC + 2} },
    { "xsr.misc3", translate_xsr, (uint32_t[]){MISC + 3} },
    { "xsr.prid", translate_xsr, (uint32_t[]){PRID} },
    { "xsr.ps", translate_xsr, (uint32_t[]){PS} },
    { "xsr.ptevaddr", translate_xsr, (uint32_t[]){PTEVADDR} },
    { "xsr.rasid", translate_xsr, (uint32_t[]){RASID} },
    { "xsr.sar", translate_xsr, (uint32_t[]){SAR} },
    { "xsr.scompare1", translate_xsr, (uint32_t[]){SCOMPARE1} },
    { "xsr.vecbase", translate_xsr, (uint32_t[]){VECBASE} },
    { "xsr.windowbase", translate_xsr, (uint32_t[]){WINDOW_BASE} },
    { "xsr.windowstart", translate_xsr, (uint32_t[]){WINDOW_START} },
};

const XtensaOpcodeTranslators core_opcodes = {
    .num_translators = ARRAY_SIZE(core_map),
    .translator = core_map,
};



static void translate_abs_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_abs_s(cpu_FR[arg[0]], cpu_FR[arg[1]]);
    }
}

static void translate_add_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_add_s(cpu_FR[arg[0]], cpu_env,
                         cpu_FR[arg[1]], cpu_FR[arg[2]]);
    }
}

enum {
    COMPARE_UN,
    COMPARE_OEQ,
    COMPARE_UEQ,
    COMPARE_OLT,
    COMPARE_ULT,
    COMPARE_OLE,
    COMPARE_ULE,
};

static void translate_compare_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    static void (* const helper[])(TCGv_env env, TCGv_i32 bit,
                                   TCGv_i32 s, TCGv_i32 t) = {
        [COMPARE_UN] = gen_helper_un_s,
        [COMPARE_OEQ] = gen_helper_oeq_s,
        [COMPARE_UEQ] = gen_helper_ueq_s,
        [COMPARE_OLT] = gen_helper_olt_s,
        [COMPARE_ULT] = gen_helper_ult_s,
        [COMPARE_OLE] = gen_helper_ole_s,
        [COMPARE_ULE] = gen_helper_ule_s,
    };

    if (gen_check_cpenable(dc, 0)) {
        TCGv_i32 bit = tcg_const_i32(1 << arg[0]);

        helper[par[0]](cpu_env, bit, cpu_FR[arg[1]], cpu_FR[arg[2]]);
        tcg_temp_free(bit);
    }
}

static void translate_float_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[1]) && gen_check_cpenable(dc, 0)) {
        TCGv_i32 scale = tcg_const_i32(-arg[2]);

        if (par[0]) {
            gen_helper_uitof(cpu_FR[arg[0]], cpu_env, cpu_R[arg[1]], scale);
        } else {
            gen_helper_itof(cpu_FR[arg[0]], cpu_env, cpu_R[arg[1]], scale);
        }
        tcg_temp_free(scale);
    }
}

static void translate_ftoi_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0]) && gen_check_cpenable(dc, 0)) {
        TCGv_i32 rounding_mode = tcg_const_i32(par[0]);
        TCGv_i32 scale = tcg_const_i32(arg[2]);

        if (par[1]) {
            gen_helper_ftoui(cpu_R[arg[0]], cpu_FR[arg[1]],
                             rounding_mode, scale);
        } else {
            gen_helper_ftoi(cpu_R[arg[0]], cpu_FR[arg[1]],
                            rounding_mode, scale);
        }
        tcg_temp_free(rounding_mode);
        tcg_temp_free(scale);
    }
}

static void translate_ldsti(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[1]) && gen_check_cpenable(dc, 0)) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_addi_i32(addr, cpu_R[arg[1]], arg[2]);
        gen_load_store_alignment(dc, 2, addr, false);
        if (par[0]) {
            tcg_gen_qemu_st32(cpu_FR[arg[0]], addr, dc->cring);
        } else {
            tcg_gen_qemu_ld32u(cpu_FR[arg[0]], addr, dc->cring);
        }
        if (par[1]) {
            tcg_gen_mov_i32(cpu_R[arg[1]], addr);
        }
        tcg_temp_free(addr);
    }
}

static void translate_ldstx(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check2(dc, arg[1], arg[2]) && gen_check_cpenable(dc, 0)) {
        TCGv_i32 addr = tcg_temp_new_i32();

        tcg_gen_add_i32(addr, cpu_R[arg[1]], cpu_R[arg[2]]);
        gen_load_store_alignment(dc, 2, addr, false);
        if (par[0]) {
            tcg_gen_qemu_st32(cpu_FR[arg[0]], addr, dc->cring);
        } else {
            tcg_gen_qemu_ld32u(cpu_FR[arg[0]], addr, dc->cring);
        }
        if (par[1]) {
            tcg_gen_mov_i32(cpu_R[arg[1]], addr);
        }
        tcg_temp_free(addr);
    }
}

static void translate_madd_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_madd_s(cpu_FR[arg[0]], cpu_env,
                          cpu_FR[arg[0]], cpu_FR[arg[1]], cpu_FR[arg[2]]);
    }
}

static void translate_mov_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        tcg_gen_mov_i32(cpu_FR[arg[0]], cpu_FR[arg[1]]);
    }
}

static void translate_movcond_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[2]) && gen_check_cpenable(dc, 0)) {
        TCGv_i32 zero = tcg_const_i32(0);

        tcg_gen_movcond_i32(par[0], cpu_FR[arg[0]],
                            cpu_R[arg[2]], zero,
                            cpu_FR[arg[1]], cpu_FR[arg[2]]);
        tcg_temp_free(zero);
    }
}

static void translate_movp_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        TCGv_i32 zero = tcg_const_i32(0);
        TCGv_i32 tmp = tcg_temp_new_i32();

        tcg_gen_andi_i32(tmp, cpu_SR[BR], 1 << arg[2]);
        tcg_gen_movcond_i32(par[0],
                            cpu_FR[arg[0]], tmp, zero,
                            cpu_FR[arg[1]], cpu_FR[arg[0]]);
        tcg_temp_free(tmp);
        tcg_temp_free(zero);
    }
}

static void translate_mul_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_mul_s(cpu_FR[arg[0]], cpu_env,
                         cpu_FR[arg[1]], cpu_FR[arg[2]]);
    }
}

static void translate_msub_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_msub_s(cpu_FR[arg[0]], cpu_env,
                          cpu_FR[arg[0]], cpu_FR[arg[1]], cpu_FR[arg[2]]);
    }
}

static void translate_neg_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_neg_s(cpu_FR[arg[0]], cpu_FR[arg[1]]);
    }
}

static void translate_rfr_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[0]) &&
        gen_check_cpenable(dc, 0)) {
        tcg_gen_mov_i32(cpu_R[arg[0]], cpu_FR[arg[1]]);
    }
}

static void translate_sub_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_check_cpenable(dc, 0)) {
        gen_helper_sub_s(cpu_FR[arg[0]], cpu_env,
                         cpu_FR[arg[1]], cpu_FR[arg[2]]);
    }
}

static void translate_wfr_s(DisasContext *dc, uint32_t arg[], uint32_t par[])
{
    if (gen_window_check1(dc, arg[1]) &&
        gen_check_cpenable(dc, 0)) {
        tcg_gen_mov_i32(cpu_FR[arg[0]], cpu_R[arg[1]]);
    }
}

static const XtensaOpcodeMap fpu2000_map[] = {
    { "abs.s", translate_abs_s },
    { "add.s", translate_add_s },
    { "ceil.s", translate_ftoi_s, (uint32_t[]){float_round_up, false} },
    { "float.s", translate_float_s, (uint32_t[]){false} },
    { "floor.s", translate_ftoi_s, (uint32_t[]){float_round_down, false} },
    { "lsi", translate_ldsti, (uint32_t[]){false, false} },
    { "lsiu", translate_ldsti, (uint32_t[]){false, true} },
    { "lsx", translate_ldstx, (uint32_t[]){false, false} },
    { "lsxu", translate_ldstx, (uint32_t[]){false, true} },
    { "madd.s", translate_madd_s },
    { "mov.s", translate_mov_s },
    { "moveqz.s", translate_movcond_s, (uint32_t[]){TCG_COND_EQ} },
    { "movf.s", translate_movp_s, (uint32_t[]){TCG_COND_EQ} },
    { "movgez.s", translate_movcond_s, (uint32_t[]){TCG_COND_GE} },
    { "movltz.s", translate_movcond_s, (uint32_t[]){TCG_COND_LT} },
    { "movnez.s", translate_movcond_s, (uint32_t[]){TCG_COND_NE} },
    { "movt.s", translate_movp_s, (uint32_t[]){TCG_COND_NE} },
    { "msub.s", translate_msub_s },
    { "mul.s", translate_mul_s },
    { "neg.s", translate_neg_s },
    { "oeq.s", translate_compare_s, (uint32_t[]){COMPARE_OEQ} },
    { "ole.s", translate_compare_s, (uint32_t[]){COMPARE_OLE} },
    { "olt.s", translate_compare_s, (uint32_t[]){COMPARE_OLT} },
    { "rfr.s", translate_rfr_s },
    { "round.s", translate_ftoi_s, (uint32_t[]){float_round_nearest_even, false} },
    { "ssi", translate_ldsti, (uint32_t[]){true, false} },
    { "ssiu", translate_ldsti, (uint32_t[]){true, true} },
    { "ssx", translate_ldstx, (uint32_t[]){true, false} },
    { "ssxu", translate_ldstx, (uint32_t[]){true, true} },
    { "sub.s", translate_sub_s },
    { "trunc.s", translate_ftoi_s, (uint32_t[]){float_round_to_zero, false} },
    { "ueq.s", translate_compare_s, (uint32_t[]){COMPARE_UEQ} },
    { "ufloat.s", translate_float_s, (uint32_t[]){true} },
    { "ule.s", translate_compare_s, (uint32_t[]){COMPARE_ULE} },
    { "ult.s", translate_compare_s, (uint32_t[]){COMPARE_ULT} },
    { "un.s", translate_compare_s, (uint32_t[]){COMPARE_UN} },
    { "utrunc.s", translate_ftoi_s, (uint32_t[]){float_round_to_zero, true} },
    { "wfr.s", translate_wfr_s },
};

const XtensaOpcodeTranslators fpu2000_opcodes = {
    .num_translators = ARRAY_SIZE(fpu2000_map),
    .translator = fpu2000_map,
};

static int compare_opcode_map(const void *a, const void *b)
{
    return strcmp((const char *)a,
                  ((const XtensaOpcodeMap *)b)->name);
}

XtensaOpcodeMap *
xtensa_find_opcode_map(const XtensaOpcodeTranslators *t,
                       const char *name)
{
    XtensaOpcodeMap *map;

    if (!t) {
        t = &core_opcodes;
    }
    map = bsearch(name, t->translator, t->num_translators,
                  sizeof(XtensaOpcodeMap), compare_opcode_map);
    return map;
}
