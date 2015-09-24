/*
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
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "elf.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "hw/char/serial.h"
#include "net/net.h"
#include "hw/sysbus.h"
#include "hw/block/flash.h"
#include "sysemu/block-backend.h"
#include "sysemu/char.h"
#include "sysemu/device_tree.h"
#include "qemu/error-report.h"
#include "bootparam.h"

typedef struct LxBoardDesc {
    hwaddr flash_base;
    size_t flash_size;
    size_t flash_boot_base;
    size_t flash_sector_size;
    size_t sram_size;
} LxBoardDesc;

typedef struct Lx60FpgaState {
    MemoryRegion iomem;
    uint32_t leds;
    uint32_t switches;
} Lx60FpgaState;

static void lx60_fpga_reset(void *opaque)
{
    Lx60FpgaState *s = opaque;

    s->leds = 0;
    s->switches = 0;
}

static uint64_t lx60_fpga_read(void *opaque, hwaddr addr,
        unsigned size)
{
    Lx60FpgaState *s = opaque;

    switch (addr) {
    case 0x0: /*build date code*/
        return 0x09272011;

    case 0x4: /*processor clock frequency, Hz*/
        return 10000000;

    case 0x8: /*LEDs (off = 0, on = 1)*/
        return s->leds;

    case 0xc: /*DIP switches (off = 0, on = 1)*/
        return s->switches;
    }
    return 0;
}

static void lx60_fpga_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
    Lx60FpgaState *s = opaque;

    switch (addr) {
    case 0x8: /*LEDs (off = 0, on = 1)*/
        s->leds = val;
        break;

    case 0x10: /*board reset*/
        if (val == 0xdead) {
            qemu_system_reset_request();
        }
        break;
    }
}

static const MemoryRegionOps lx60_fpga_ops = {
    .read = lx60_fpga_read,
    .write = lx60_fpga_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Lx60FpgaState *lx60_fpga_init(MemoryRegion *address_space,
        hwaddr base)
{
    Lx60FpgaState *s = g_malloc(sizeof(Lx60FpgaState));

    memory_region_init_io(&s->iomem, NULL, &lx60_fpga_ops, s,
            "lx60.fpga", 0x10000);
    memory_region_add_subregion(address_space, base, &s->iomem);
    lx60_fpga_reset(s);
    qemu_register_reset(lx60_fpga_reset, s);
    return s;
}

typedef struct Lx60SpiState {
    MemoryRegion iomem;
    uint32_t start;
    uint32_t data;
    int64_t start_time;
} Lx60SpiState;

static void lx60_spi_reset(void *opaque)
{
    Lx60SpiState *s = opaque;

    s->start = 0;
    s->data = 0;
    s->start_time = 0;
}

static uint64_t lx60_spi_read(void *opaque, hwaddr addr,
        unsigned size)
{
    Lx60SpiState *s = opaque;

    switch (addr) {
    case 0x0: /*start*/
        return s->start;

    case 0x4: /*busy*/
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->start_time < 100000;
    }
    return 0;
}

static void lx60_spi_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
    Lx60SpiState *s = opaque;

    switch (addr) {
    case 0x0: /*start*/
        if ((s->start ^ val) & 1) {
            s->start_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        }
        s->start = val & 1;
        break;

    case 0x8: /*data*/
        s->data = val;
        break;
    }
}

static const MemoryRegionOps lx60_spi_ops = {
    .read = lx60_spi_read,
    .write = lx60_spi_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Lx60SpiState *lx60_spi_init(MemoryRegion *address_space,
        hwaddr base)
{
    Lx60SpiState *s = g_malloc(sizeof(Lx60SpiState));

    memory_region_init_io(&s->iomem, NULL, &lx60_spi_ops, s,
            "lx60.spi", 0x10000);
    memory_region_add_subregion(address_space, base, &s->iomem);
    lx60_spi_reset(s);
    qemu_register_reset(lx60_spi_reset, s);
    return s;
}

typedef struct Lx60I2SState {
    MemoryRegion iomem;
    uint32_t start;
    uint32_t data;
    int64_t start_time;
} Lx60I2SState;

static void lx60_i2s_reset(void *opaque)
{
    Lx60I2SState *s = opaque;

    s->start = 0;
    s->data = 0;
    s->start_time = 0;
}

static uint64_t lx60_i2s_read(void *opaque, hwaddr addr,
        unsigned size)
{
    Lx60I2SState *s = opaque;

    printf("%s: %08lx<%u>\n", __func__, addr, size);
    switch (addr) {
    case 0x0: /*start*/
        return s->start;

    case 0x4: /*busy*/
        return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - s->start_time < 100000;
    }
    return 0;
}

static void lx60_i2s_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
    Lx60I2SState *s = opaque;

    printf("%s: %08lx<%u> = %08lx\n", __func__, addr, size, val);
    switch (addr) {
    case 0x0: /*start*/
        if ((s->start ^ val) & 1) {
            s->start_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        }
        s->start = val & 1;
        break;

    case 0x8: /*data*/
        s->data = val;
        break;
    }
}

static const MemoryRegionOps lx60_i2s_ops = {
    .read = lx60_i2s_read,
    .write = lx60_i2s_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Lx60I2SState *lx60_i2s_init(MemoryRegion *address_space,
        hwaddr base)
{
    Lx60I2SState *s = g_malloc(sizeof(Lx60I2SState));

    memory_region_init_io(&s->iomem, NULL, &lx60_i2s_ops, s,
            "lx60.i2s", 0x10000);
    memory_region_add_subregion(address_space, base, &s->iomem);
    lx60_i2s_reset(s);
    qemu_register_reset(lx60_i2s_reset, s);
    return s;
}


static void lx60_net_init(MemoryRegion *address_space,
        hwaddr base,
        hwaddr descriptors,
        hwaddr buffers,
        qemu_irq irq, NICInfo *nd)
{
    DeviceState *dev;
    SysBusDevice *s;
    MemoryRegion *ram;

    dev = qdev_create(NULL, "open_eth");
    qdev_set_nic_properties(dev, nd);
    qdev_init_nofail(dev);

    s = SYS_BUS_DEVICE(dev);
    sysbus_connect_irq(s, 0, irq);
    memory_region_add_subregion(address_space, base,
            sysbus_mmio_get_region(s, 0));
    memory_region_add_subregion(address_space, descriptors,
            sysbus_mmio_get_region(s, 1));

    ram = g_malloc(sizeof(*ram));
    memory_region_init_ram(ram, OBJECT(s), "open_eth.ram", 16384,
                           &error_fatal);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(address_space, buffers, ram);
}

static pflash_t *xtfpga_flash_init(MemoryRegion *address_space,
                                   const LxBoardDesc *board,
                                   DriveInfo *dinfo, int be)
{
    SysBusDevice *s;
    DeviceState *dev = qdev_create(NULL, "cfi.pflash01");

    qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo),
                        &error_abort);
    qdev_prop_set_uint32(dev, "num-blocks",
                         board->flash_size / board->flash_sector_size);
    qdev_prop_set_uint64(dev, "sector-length", board->flash_sector_size);
    qdev_prop_set_uint8(dev, "width", 2);
    qdev_prop_set_bit(dev, "big-endian", be);
    qdev_prop_set_uint16(dev, "id1", 0x89);
    qdev_prop_set_uint16(dev, "id2", 0x89);
    qdev_prop_set_uint16(dev, "id3", 0x66);
    qdev_prop_set_string(dev, "name", "lx60.io.flash");
    qdev_init_nofail(dev);
    s = SYS_BUS_DEVICE(dev);
    memory_region_add_subregion(address_space, board->flash_base,
                                sysbus_mmio_get_region(s, 0));
    return OBJECT_CHECK(pflash_t, (dev), "cfi.pflash01");
}

static uint64_t translate_phys_addr(void *opaque, uint64_t addr)
{
    XtensaCPU *cpu = opaque;

    return cpu_get_phys_page_debug(CPU(cpu), addr);
}

static void lx60_reset(void *opaque)
{
    XtensaCPU *cpu = opaque;

    cpu_reset(CPU(cpu));
}

static uint64_t lx60_io_read(void *opaque, hwaddr addr,
        unsigned size)
{
    return 0;
}

static void lx60_io_write(void *opaque, hwaddr addr,
        uint64_t val, unsigned size)
{
}

static const MemoryRegionOps lx60_io_ops = {
    .read = lx60_io_read,
    .write = lx60_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void lx_init(const LxBoardDesc *board, MachineState *machine)
{
#ifdef TARGET_WORDS_BIGENDIAN
    int be = 1;
#else
    int be = 0;
#endif
    MemoryRegion *system_memory = get_system_memory();
    XtensaCPU *cpu = NULL;
    CPUXtensaState *env = NULL;
    MemoryRegion *ram, *rom, *system_io;
    DriveInfo *dinfo;
    pflash_t *flash = NULL;
    QemuOpts *machine_opts = qemu_get_machine_opts();
    const char *cpu_model = machine->cpu_model;
    const char *kernel_filename = qemu_opt_get(machine_opts, "kernel");
    const char *kernel_cmdline = qemu_opt_get(machine_opts, "append");
    const char *dtb_filename = qemu_opt_get(machine_opts, "dtb");
    const char *initrd_filename = qemu_opt_get(machine_opts, "initrd");
    const unsigned system_io_size = 224 * 1024 * 1024;
    int n;

    enum {
        XTENSA_NO_MMU,
        XTENSA_MMU,
    } mmu;

    static const struct {
        hwaddr ram;
        hwaddr rom;
        hwaddr io[2];
    } base[2] = {
        [XTENSA_NO_MMU] = {
            .ram = 0x60000000,
            .rom = 0x50000000,
            .io = {
                0x90000000,
                0x70000000,
            },
        },
        [XTENSA_MMU] = {
            .ram = 0,
            .rom = 0xfe000000,
            .io = {
                0xf0000000,
            },
        },
    };

    if (!cpu_model) {
        cpu_model = XTENSA_DEFAULT_CPU_MODEL;
    }

    for (n = 0; n < smp_cpus; n++) {
        cpu = cpu_xtensa_init(cpu_model);
        if (cpu == NULL) {
            error_report("unable to find CPU definition '%s'",
                         cpu_model);
            exit(EXIT_FAILURE);
        }
        env = &cpu->env;

        env->sregs[PRID] = n;
        qemu_register_reset(lx60_reset, cpu);
        /* Need MMU initialized prior to ELF loading,
         * so that ELF gets loaded into virtual addresses
         */
        cpu_reset(CPU(cpu));
    }

    mmu = xtensa_option_enabled(env->config, XTENSA_OPTION_MMU) ?
        XTENSA_MMU : XTENSA_NO_MMU;
    ram = g_malloc(sizeof(*ram));
    memory_region_init_ram(ram, NULL, "lx60.dram", machine->ram_size,
                           &error_fatal);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(system_memory, base[mmu].ram, ram);

    system_io = g_malloc(sizeof(*system_io));
    memory_region_init_io(system_io, NULL, &lx60_io_ops, NULL, "lx60.io",
                          system_io_size);
    memory_region_add_subregion(system_memory, base[mmu].io[0], system_io);
    if (base[mmu].io[1]) {
        MemoryRegion *io = g_malloc(sizeof(*io));

        memory_region_init_alias(io, NULL, "lx60.io.cached",
                                 system_io, 0, system_io_size);
        memory_region_add_subregion(system_memory, base[mmu].io[1], io);
    }
    lx60_fpga_init(system_io, 0x0d020000);
    lx60_i2s_init(system_io, 0x0d080000);
    lx60_spi_init(system_io, 0x0d0a0000);
    if (nd_table[0].used) {
        lx60_net_init(system_io, 0x0d030000, 0x0d030400, 0x0d800000,
                xtensa_get_extint(env, 1), nd_table);
    }

    if (!serial_hds[0]) {
        serial_hds[0] = qemu_chr_new("serial0", "null");
    }

    serial_mm_init(system_io, 0x0d050020, 2, xtensa_get_extint(env, 0),
            115200, serial_hds[0], DEVICE_NATIVE_ENDIAN);

    dinfo = drive_get(IF_PFLASH, 0, 0);
    if (dinfo) {
        flash = xtfpga_flash_init(system_io, board, dinfo, be);
    }

    /* Use presence of kernel file name as 'boot from SRAM' switch. */
    if (kernel_filename) {
        uint32_t entry_point = env->pc;
        size_t bp_size = 3 * get_tag_size(0); /* first/last and memory tags */
        uint32_t tagptr = base[mmu].rom + board->sram_size;
        uint32_t cur_tagptr;
        BpMemInfo memory_location = {
            .type = tswap32(MEMORY_TYPE_CONVENTIONAL),
            .start = tswap32(base[mmu].ram),
            .end = tswap32(base[mmu].ram + machine->ram_size),
        };
        uint32_t lowmem_end = machine->ram_size < 0x08000000 ?
            machine->ram_size : 0x08000000;
        uint32_t cur_lowmem = QEMU_ALIGN_UP(lowmem_end / 2, 4096);

        lowmem_end += base[mmu].ram;
        cur_lowmem += base[mmu].ram;

        rom = g_malloc(sizeof(*rom));
        memory_region_init_ram(rom, NULL, "lx60.sram", board->sram_size,
                               &error_fatal);
        vmstate_register_ram_global(rom);
        memory_region_add_subregion(system_memory, base[mmu].rom, rom);

        if (kernel_cmdline) {
            bp_size += get_tag_size(strlen(kernel_cmdline) + 1);
        }
        if (dtb_filename) {
            bp_size += get_tag_size(sizeof(uint32_t));
        }
        if (initrd_filename) {
            bp_size += get_tag_size(sizeof(BpMemInfo));
        }

        /* Put kernel bootparameters to the end of that SRAM */
        tagptr = (tagptr - bp_size) & ~0xff;
        cur_tagptr = put_tag(tagptr, BP_TAG_FIRST, 0, NULL);
        cur_tagptr = put_tag(cur_tagptr, BP_TAG_MEMORY,
                             sizeof(memory_location), &memory_location);

        if (kernel_cmdline) {
            cur_tagptr = put_tag(cur_tagptr, BP_TAG_COMMAND_LINE,
                                 strlen(kernel_cmdline) + 1, kernel_cmdline);
        }
        if (dtb_filename) {
            int fdt_size;
            void *fdt = load_device_tree(dtb_filename, &fdt_size);
            uint32_t dtb_addr = tswap32(cur_lowmem);

            if (!fdt) {
                error_report("could not load DTB '%s'", dtb_filename);
                exit(EXIT_FAILURE);
            }

            cpu_physical_memory_write(cur_lowmem, fdt, fdt_size);
            cur_tagptr = put_tag(cur_tagptr, BP_TAG_FDT,
                                 sizeof(dtb_addr), &dtb_addr);
            cur_lowmem = QEMU_ALIGN_UP(cur_lowmem + fdt_size, 4096);
        }
        if (initrd_filename) {
            BpMemInfo initrd_location = { 0 };
            int initrd_size = load_ramdisk(initrd_filename, cur_lowmem,
                                           lowmem_end - cur_lowmem);

            if (initrd_size < 0) {
                initrd_size = load_image_targphys(initrd_filename,
                                                  cur_lowmem,
                                                  lowmem_end - cur_lowmem);
            }
            if (initrd_size < 0) {
                error_report("could not load initrd '%s'", initrd_filename);
                exit(EXIT_FAILURE);
            }
            initrd_location.start = tswap32(cur_lowmem);
            initrd_location.end = tswap32(cur_lowmem + initrd_size);
            cur_tagptr = put_tag(cur_tagptr, BP_TAG_INITRD,
                                 sizeof(initrd_location), &initrd_location);
            cur_lowmem = QEMU_ALIGN_UP(cur_lowmem + initrd_size, 4096);
        }
        cur_tagptr = put_tag(cur_tagptr, BP_TAG_LAST, 0, NULL);
        env->regs[2] = tagptr;

        uint64_t elf_entry;
        uint64_t elf_lowaddr;
        int success = load_elf(kernel_filename, translate_phys_addr, cpu,
                &elf_entry, &elf_lowaddr, NULL, be, EM_XTENSA, 0, 0);
        if (success > 0) {
            entry_point = elf_entry;
        } else {
            hwaddr ep;
            int is_linux;
            success = load_uimage(kernel_filename, &ep, NULL, &is_linux,
                                  translate_phys_addr, cpu);
            if (success > 0 && is_linux) {
                entry_point = ep;
            } else {
                error_report("could not load kernel '%s'",
                             kernel_filename);
                exit(EXIT_FAILURE);
            }
        }
        if (entry_point != env->pc) {
            static const uint8_t jx_a0[] = {
#ifdef TARGET_WORDS_BIGENDIAN
                0x0a, 0, 0,
#else
                0xa0, 0, 0,
#endif
            };
            env->regs[0] = entry_point;
            cpu_physical_memory_write(env->pc, jx_a0, sizeof(jx_a0));
        }
    } else {
        if (flash) {
            MemoryRegion *flash_mr = pflash_cfi01_get_memory(flash);
            MemoryRegion *flash_io = g_malloc(sizeof(*flash_io));

            memory_region_init_alias(flash_io, NULL, "lx60.flash",
                    flash_mr, board->flash_boot_base,
                    board->flash_size - board->flash_boot_base < 0x02000000 ?
                    board->flash_size - board->flash_boot_base : 0x02000000);
            memory_region_add_subregion(system_memory, base[mmu].rom,
                    flash_io);
        }
    }
}

static void xtensa_lx60_init(MachineState *machine)
{
    static const LxBoardDesc lx60_board = {
        .flash_base = 0x08000000,
        .flash_size = 0x00400000,
        .flash_sector_size = 0x10000,
        .sram_size = 0x20000,
    };
    lx_init(&lx60_board, machine);
}

static void xtensa_lx200_init(MachineState *machine)
{
    static const LxBoardDesc lx200_board = {
        .flash_base = 0x08000000,
        .flash_size = 0x01000000,
        .flash_sector_size = 0x20000,
        .sram_size = 0x2000000,
    };
    lx_init(&lx200_board, machine);
}

static void xtensa_ml605_init(MachineState *machine)
{
    static const LxBoardDesc ml605_board = {
        .flash_base = 0x08000000,
        .flash_size = 0x01000000,
        .flash_sector_size = 0x20000,
        .sram_size = 0x2000000,
    };
    lx_init(&ml605_board, machine);
}

static void xtensa_kc705_init(MachineState *machine)
{
    static const LxBoardDesc kc705_board = {
        .flash_base = 0x00000000,
        .flash_size = 0x08000000,
        .flash_boot_base = 0x06000000,
        .flash_sector_size = 0x20000,
        .sram_size = 0x2000000,
    };
    lx_init(&kc705_board, machine);
}

static void xtensa_lx60_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "lx60 EVB (" XTENSA_DEFAULT_CPU_MODEL ")";
    mc->init = xtensa_lx60_init;
    mc->max_cpus = 4;
}

static const TypeInfo xtensa_lx60_type = {
    .name = MACHINE_TYPE_NAME("lx60"),
    .parent = TYPE_MACHINE,
    .class_init = xtensa_lx60_class_init,
};

static void xtensa_lx200_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "lx200 EVB (" XTENSA_DEFAULT_CPU_MODEL ")";
    mc->init = xtensa_lx200_init;
    mc->max_cpus = 4;
}

static const TypeInfo xtensa_lx200_type = {
    .name = MACHINE_TYPE_NAME("lx200"),
    .parent = TYPE_MACHINE,
    .class_init = xtensa_lx200_class_init,
};

static void xtensa_ml605_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "ml605 EVB (" XTENSA_DEFAULT_CPU_MODEL ")";
    mc->init = xtensa_ml605_init;
    mc->max_cpus = 4;
}

static const TypeInfo xtensa_ml605_type = {
    .name = MACHINE_TYPE_NAME("ml605"),
    .parent = TYPE_MACHINE,
    .class_init = xtensa_ml605_class_init,
};

static void xtensa_kc705_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "kc705 EVB (" XTENSA_DEFAULT_CPU_MODEL ")";
    mc->init = xtensa_kc705_init;
    mc->max_cpus = 4;
}

static const TypeInfo xtensa_kc705_type = {
    .name = MACHINE_TYPE_NAME("kc705"),
    .parent = TYPE_MACHINE,
    .class_init = xtensa_kc705_class_init,
};

static void xtensa_lx_machines_init(void)
{
    type_register_static(&xtensa_lx60_type);
    type_register_static(&xtensa_lx200_type);
    type_register_static(&xtensa_ml605_type);
    type_register_static(&xtensa_kc705_type);
}

type_init(xtensa_lx_machines_init)
