// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2013
 * Andre Przywara, Linaro <andre.przywara@linaro.org>
 *
 * Routines to transition ARMv7 processors from secure into non-secure state
 * and from non-secure SVC into HYP mode
 * needed to enable ARMv7 virtualization for current hypervisors
 */
#include <config.h>
#include <asm/armv7.h>
#include <asm/cache.h>
#include <asm/gic.h>
#include <asm/io.h>
#include <asm/secure.h>
#include "debug.h"

uintptr_t secure_reloc_off;

static unsigned int read_id_pfr1(void)
{
	unsigned int reg;

	__asm__ __volatile__("mrc p15, 0, %0, c0, c1, 1\n" : "=r"(reg));
	return reg;
}

static unsigned long get_gicd_base_address(void)
{
#ifdef CONFIG_ARM_GIC_BASE_ADDRESS
	return CONFIG_ARM_GIC_BASE_ADDRESS + GIC_DIST_OFFSET;
#else
	unsigned periphbase;

	/* get the GIC base address from the CBAR register */
	__asm__ __volatile__("mrc p15, 4, %0, c15, c0, 0\n" : "=r"(periphbase));

	/* the PERIPHBASE can be mapped above 4 GB (lower 8 bits used to
	 * encode this). Bail out here since we cannot access this without
	 * enabling paging.
	 */
	if ((periphbase & 0xff) != 0) {
		error("nonsec: PERIPHBASE is above 4 GB, no access.\r\n");
		return -1;
	}

	return (periphbase & CBAR_MASK) + GIC_DIST_OFFSET;
#endif
}

/* Define a specific version of this function to enable any available
 * hardware protections for the reserved region */
void __weak protect_secure_section(void) {}

static void relocate_secure_section(void)
{
#ifdef CONFIG_ARMV7_SECURE_BASE
	size_t sz = __secure_end - __secure_start;
	unsigned long szflush = ALIGN(sz + 1, CONFIG_SYS_CACHELINE_SIZE);

	memcpy((void *)CONFIG_ARMV7_SECURE_BASE, __secure_start, sz);
	secure_reloc_off = (uintptr_t)__secure_start - CONFIG_ARMV7_SECURE_BASE;

	flush_dcache_range(CONFIG_ARMV7_SECURE_BASE,
			   CONFIG_ARMV7_SECURE_BASE + szflush);
	protect_secure_section();
	invalidate_icache_all();
#endif
}

static void kick_secondary_cpus_gic(unsigned long gicdaddr)
{
	/* kick all CPUs (except this one) by writing to GICD_SGIR */
	writel(1U << 24, gicdaddr + GICD_SGIR);
}

void __weak smp_kick_all_cpus(void)
{
	unsigned long gic_dist_addr;

	gic_dist_addr = get_gicd_base_address();
	if (gic_dist_addr == -1)
		return;

	kick_secondary_cpus_gic(gic_dist_addr);
}

__weak void psci_board_init(void)
{
}

int armv7_init_nonsec(void)
{
	unsigned int reg;
	unsigned itlinesnr, i;
	unsigned long gic_dist_addr;

	reg = read_id_pfr1();
	if ((reg & 0xF0) == 0) {
		error("nonsec: Security extensions not implemented.\r\n");
		return -1;
	}
	debug("NSEC: pfr1 OK\r\n");

	gic_dist_addr = get_gicd_base_address();
	if (gic_dist_addr == -1)
		return -1;
	debug("NSEC: gicd_addr=0x%08lx\r\n", gic_dist_addr);

	writel(readl(gic_dist_addr + GICD_CTLR) | 0x03, gic_dist_addr + GICD_CTLR);
	itlinesnr = readl(gic_dist_addr + GICD_TYPER) & 0x1f;
	debug("NSEC: GICD ctlr set, itlinesnr=%u\r\n", itlinesnr);

	for (i = 1; i <= itlinesnr; i++)
		writel((unsigned)-1, gic_dist_addr + GICD_IGROUPRn + 4 * i);
	debug("NSEC: IGROUPR set\r\n");

	psci_board_init();   /* -> sudah tercetak "SPC: NS hand-off confirmed" */

	relocate_secure_section();
	debug("NSEC: secure section relocated\r\n");   /* <- KUNCI: kalau ini TIDAK muncul, masalahnya di relocate_secure_section/CONFIG_ARMV7_SECURE_BASE */

#ifndef CONFIG_ARMV7_PSCI
	smp_set_core_boot_addr((unsigned long)secure_ram_addr(_smp_pen), -1);
	smp_kick_all_cpus();
	debug("NSEC: secondary cpus kicked\r\n");
#endif

	debug("NSEC: about to call _nonsec_init via SMC\r\n");   /* <- KUNCI: kalau ini muncul tapi tidak pernah lanjut, masalahnya PERSIS di instruksi SMC/_nonsec_init itu sendiri */
	secure_ram_addr(_nonsec_init)();
	debug("NSEC: returned from _nonsec_init (unexpected if PSCI-based)\r\n");
	return 0;
}
