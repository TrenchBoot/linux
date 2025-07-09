/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_TIMER_H
#define BOOT_COMPRESSED_TIMER_H

/* Calibrate CPU hz with PIT running at known clock frequency */
void pit_calibrate(void);

/* Timer functions */
void early_mdelay(u32 ms);
void early_udelay(u32 us);
ktime_t early_now_ms(void);

#endif /* BOOT_COMPRESSED_TIMER_H */
