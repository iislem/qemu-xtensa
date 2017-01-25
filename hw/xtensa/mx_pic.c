/*
 * Copyright (c) 2013 - 2017, Max Filippov, Open Source and Linux Lab.
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
#include "hw/hw.h"
#include "qemu/log.h"
#include "qemu/timer.h"

#define MX_MAX_CPU 32
#define MX_MAX_IRQ 32

#define MIROUT 0x0
#define MIPICAUSE 0x100
#define MIPISET 0x140
#define MIENG 0x180
#define MIENGSET 0x184
#define MIASG 0x188
#define MIASGSET 0x18c
#define MIPIPART 0x190
#define SYSCFGID 0x1a0
#define MPSCORE 0x200
#define CCON 0x220

struct XtensaMxPic {
    unsigned n_cpu;
    unsigned n_irq;

    uint32_t ext_irq_state;
    uint32_t mieng;
    uint32_t miasg;
    uint32_t mirout[MX_MAX_IRQ];
    uint32_t mipipart;
    uint32_t runstall;

    QEMUTimer *timer;
    void **irq_inputs;
    XtensaIRQController irq_controller;
    struct XtensaMxPicCpu {
        XtensaMxPic *mx;
        CPUXtensaState *env;
        uint32_t mipicause;
        uint32_t mirout_cache;
        uint32_t irq_state_cache;
        uint32_t ccon;
        MemoryRegion reg;
    } cpu[MX_MAX_CPU];
};

static uint64_t xtensa_mx_pic_ext_reg_read(void *opaque, hwaddr offset,
                                           unsigned size)
{
    struct XtensaMxPicCpu *mx_cpu = opaque;
    struct XtensaMxPic *mx = mx_cpu->mx;

    if (offset < MIROUT + MX_MAX_IRQ) {
        return mx->mirout[offset - MIROUT];
    } else if (offset >= MIPICAUSE && offset < MIPICAUSE + MX_MAX_CPU) {
        return mx->cpu[offset - MIPICAUSE].mipicause;
    } else {
        switch (offset) {
        case MIENG:
            return mx->mieng;

        case MIASG:
            return mx->miasg;

        case MIPIPART:
            return mx->mipipart;

        case SYSCFGID:
            return ((mx->n_cpu - 1) << 18) | (mx_cpu - mx->cpu);

        case MPSCORE:
            return mx->runstall;

        case CCON:
            return mx_cpu->ccon;

        default:
            qemu_log_mask(LOG_GUEST_ERROR,
			  "unknown RER in MX PIC range: 0x%08x\n",
			  (uint32_t)offset);
            return 0;
        }
    }
}

static uint32_t xtensa_mx_pic_get_ipi_for_cpu(const XtensaMxPic *mx,
                                              unsigned cpu)
{
    uint32_t mipicause = mx->cpu[cpu].mipicause;
    uint32_t mipipart = mx->mipipart;

    return ((mipicause & 1) << (mipipart & 3)) |
        ((mipicause & 0x000e) != 0) << ((mipipart >> 2) & 3) |
        ((mipicause & 0x00f0) != 0) << ((mipipart >> 4) & 3) |
        ((mipicause & 0xff00) != 0) << ((mipipart >> 6) & 3);
}

static uint32_t xtensa_mx_pic_get_ext_irq_for_cpu(const XtensaMxPic *mx,
                                                  unsigned cpu)
{
    return ((((mx->ext_irq_state & mx->mieng) | mx->miasg) &
             mx->cpu[cpu].mirout_cache) << 2) |
        xtensa_mx_pic_get_ipi_for_cpu(mx, cpu);
}

static void xtensa_mx_pic_update_cpu(XtensaMxPic *mx, unsigned cpu)
{
    uint32_t irq = xtensa_mx_pic_get_ext_irq_for_cpu(mx, cpu);
    uint32_t changed_irq = mx->cpu[cpu].irq_state_cache ^ irq;
    XtensaIRQController *irq_controller =
        xtensa_env_get_irq_controller(mx->cpu[cpu].env);
    unsigned i;

    qemu_log_mask(CPU_LOG_INT, "%s: CPU %d, irq: %08x, changed_irq: %08x\n",
                  __func__, cpu, irq, changed_irq);
    mx->cpu[cpu].irq_state_cache = irq;
    for (i = 0; changed_irq; ++i) {
        uint32_t mask = 1 << i;

        if (changed_irq & mask) {
            void *irq_line = xtensa_get_extint(irq_controller, i);

            changed_irq ^= mask;
            qemu_set_irq(irq_line, irq & mask);
        }
    }
}

static void xtensa_mx_pic_update_all(XtensaMxPic *mx)
{
    unsigned i;
    for (i = 0; i < mx->n_cpu; ++i) {
        xtensa_mx_pic_update_cpu(mx, i);
    }
}

static void xtensa_mx_pic_ext_reg_write(void *opaque, hwaddr offset,
                                        uint64_t v, unsigned size)
{
    struct XtensaMxPicCpu *mx_cpu = opaque;
    struct XtensaMxPic *mx = mx_cpu->mx;
    unsigned cpu;

    if (offset < MIROUT + mx->n_irq) {
        mx->mirout[offset - MIROUT] = v;
        for (cpu = 0; cpu < mx->n_cpu; ++cpu) {
            uint32_t mask = 1u << (offset - MIROUT);

            if (!(mx->cpu[cpu].mirout_cache & mask) != !(v & (1u << cpu))) {
                mx->cpu[cpu].mirout_cache ^= mask;
                xtensa_mx_pic_update_cpu(mx, cpu);
            }
        }
    } else if (offset >= MIPICAUSE && offset < MIPICAUSE + mx->n_cpu) {
        cpu = offset - MIPICAUSE;
        mx->cpu[cpu].mipicause &= ~v;
        xtensa_mx_pic_update_cpu(mx, cpu);
    } else if (offset >= MIPISET && offset < MIPISET + 16) {
        for (cpu = 0; cpu < mx->n_cpu; ++cpu) {
            if (v & (1u << cpu)) {
                mx->cpu[cpu].mipicause |= 1u << (offset - MIPISET);
                xtensa_mx_pic_update_cpu(mx, cpu);
            }
        }
    } else {
        uint32_t change = 0;

        switch (offset) {
        case MIENG:
            change = mx->mieng & ~v;
            mx->mieng &= ~v;
            break;

        case MIENGSET:
            change = ~mx->mieng & v;
            mx->mieng |= v;
            break;

        case MIASG:
            change = mx->miasg & ~v;
            mx->miasg &= ~v;
            break;

        case MIASGSET:
            change = ~mx->miasg & v;
            mx->miasg |= v;
            break;

        case MIPIPART:
            change = mx->mipipart ^ v;
            mx->mipipart = v;
            break;

        case MPSCORE:
            change = mx->runstall ^ v;
            qemu_log_mask(CPU_LOG_INT,
                          "%s: RUNSTALL changed by CPU %d: %08x -> %08x\n",
                          __func__, (int)(mx_cpu - mx->cpu),
                          mx->runstall, (uint32_t)v);
            mx->runstall = v;
            for (cpu = 0; cpu < mx->n_cpu; ++cpu, change >>= 1, v >>= 1) {
                if (change & 1) {
                    xtensa_runstall(mx->cpu[cpu].env, v & 1);
                }
            }
            cpu_exit(CPU(xtensa_env_get_cpu(mx_cpu->env)));
            break;

        case CCON:
            mx_cpu->ccon = v & 0x1;
            break;

        default:
            qemu_log_mask(LOG_GUEST_ERROR,
			  "unknown WER in MX PIC range: 0x%08x = 0x%08x\n",
			  (uint32_t)offset, (uint32_t)v);
            break;
        }
        if (change) {
            xtensa_mx_pic_update_all(mx);
        }
    }
}

static const MemoryRegionOps xtensa_mx_pic_ops = {
    .read = xtensa_mx_pic_ext_reg_read,
    .write = xtensa_mx_pic_ext_reg_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .unaligned = true,
    },
};

void xtensa_mx_pic_register_env(XtensaMxPic *mx, CPUXtensaState *env)
{
    struct XtensaMxPicCpu *mx_cpu = mx->cpu + mx->n_cpu;

    mx_cpu->mx = mx;
    mx_cpu->env = env;

    memory_region_init_io(&mx_cpu->reg, NULL, &xtensa_mx_pic_ops, mx_cpu,
                          "mx_pic", 0x280);
    memory_region_add_subregion(xtensa_get_er_region(env),
                                0, &mx_cpu->reg);

    ++mx->n_cpu;
}

static void xtensa_mx_pic_set_irq(void *opaque, int irq, int active)
{
    XtensaMxPic *mx = opaque;

    if (irq < mx->n_irq) {
        uint32_t old_irq_state = mx->ext_irq_state;

        if (active) {
            mx->ext_irq_state |= 1u << irq;
        } else {
            mx->ext_irq_state &= ~(1u << irq);
        }
        qemu_log_mask(CPU_LOG_INT,
                      "%s: IRQ %d, active: %d, ext_irq_state: %08x -> %08x\n",
                      __func__, irq, active, old_irq_state, mx->ext_irq_state);
        xtensa_mx_pic_update_all(mx);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: IRQ %d out of range\n",
		      __func__, irq);
    }
}

static void *xtensa_mx_pic_get_irq(void *opaque, unsigned irq)
{
    XtensaMxPic *mx = opaque;

    assert(irq < mx->n_irq);
    return mx->irq_inputs[irq + 1];
}

static void xtensa_mx_pic_timer_cb(void *opaque)
{
    XtensaMxPic *mx = opaque;
    timer_mod(mx->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              NANOSECONDS_PER_SECOND / 1000);
}

XtensaMxPic *xtensa_mx_pic_init(unsigned n_irq)
{
    XtensaMxPic *mx = calloc(1, sizeof(XtensaMxPic));
    mx->n_irq = n_irq + 1;
    mx->irq_inputs = (void **)qemu_allocate_irqs(xtensa_mx_pic_set_irq, mx,
                                                 mx->n_irq);
    mx->irq_controller.opaque = mx;
    mx->irq_controller.get_irq = xtensa_mx_pic_get_irq;
    mx->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                             xtensa_mx_pic_timer_cb, mx);
    return mx;
}

void xtensa_mx_pic_reset(void *opaque)
{
    XtensaMxPic *mx = opaque;
    unsigned i;

    mx->mieng = mx->n_irq < 32 ? (1u << mx->n_irq) - 1 : ~0u;
    mx->miasg = 0;
    mx->mipipart = 0;
    for (i = 0; i < mx->n_irq; ++i) {
        mx->mirout[i] = 1;
    }
    for (i = 0; i < mx->n_cpu; ++i) {
        mx->cpu[i].mipicause = 0;
        mx->cpu[i].mirout_cache = i ? 0 : mx->mieng;
        mx->cpu[i].ccon = 0;
    }
    mx->runstall = (1u << mx->n_cpu) - 2;
    for (i = 0; i < mx->n_cpu; ++i) {
        xtensa_runstall(mx->cpu[i].env, i > 0);
    }
    timer_mod(mx->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              NANOSECONDS_PER_SECOND / 1000);
}

XtensaIRQController *xtensa_mx_pic_get_irq_controller(XtensaMxPic *mx)
{
    return &mx->irq_controller;
}
