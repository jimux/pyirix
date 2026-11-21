/* A slice of hw/mips/sgi_octane.c: exactly the FOUR handler forms the
 * model_state reader must resolve, and the #defines they use.  The real file is
 * 13,164 lines; this fixture is what the known-answer test needs, and its
 * instructions are the real ones (comments trimmed where they do not matter).
 */

/* form 1: a direct constant on the widget offset. */
#define MGRAS_HQ_FLAG_USER_OFF     0x20010
#define MGRAS_HQ_FLAG_CLR_USER_OFF 0x20018
#define MGRAS_HQ_INTR_ENAB_OFF     0x11040
#define MGRAS_HQ_FLAG_PRIV_OFF     0x11020

/* form 2: base + offset. */
#define MGRAS_XMAP_BASE         0x71c00
#define MGRAS_XMAP_PP1SEL_OFF   0x008
#define MGRAS_XMAP_INDEX_OFF    0x088
#define MGRAS_XMAP_CONFIG_OFF   0x100
#define MGRAS_XMAP_CFGBYTE_OFF  0x108
#define MGRAS_XMAP_MAINMODE_OFF 0x200
#define MGRAS_XMAP_OVLMODE_OFF  0x280
#define MGRAS_XMAP_DIB_OFF      0x300

/* form 3: the CMAP/DAC window. */
#define MGRAS_CMAPALL_BASE  0x70c00
#define MGRAS_CMAP0_BASE    0x70400
#define MGRAS_CMAP1_BASE    0x70800
#define MGRAS_CMAP_ADDR_OFF 0x030
#define MGRAS_CMAP_PAL_OFF  0x118
#define MGRAS_DAC_BASE      0x71800
#define MGRAS_DAC_ADDR_OFF  0x010
#define MGRAS_DAC_PAL_OFF   0x090
#define MGRAS_DAC_CMD_OFF   0x110




static bool mgras_cmap_dac_write(SGIMgrasWin *s, hwaddr off, uint64_t val)
{
    uint32_t base = 0, reg;

    if (off >= MGRAS_CMAPALL_BASE && off < MGRAS_CMAPALL_BASE + 0x400) {
        base = MGRAS_CMAPALL_BASE;
    } else if (off >= MGRAS_CMAP0_BASE && off < MGRAS_CMAP0_BASE + 0x400) {
        base = MGRAS_CMAP0_BASE;
    } else if (off >= MGRAS_CMAP1_BASE && off < MGRAS_CMAP1_BASE + 0x400) {
        base = MGRAS_CMAP1_BASE;
    }
    if (base) {
        reg = off - base;
        if (reg == MGRAS_CMAP_ADDR_OFF) {
            s->cmap_addr = 0;
            return true;
        }
        if (reg == MGRAS_CMAP_PAL_OFF) {
            s->cmap_pal[s->cmap_addr] = (uint32_t)val;
            return true;
        }
        return false;
    }
    if (off >= MGRAS_DAC_BASE && off < MGRAS_DAC_BASE + 0x400) {
        reg = off - MGRAS_DAC_BASE;
        if (reg == MGRAS_DAC_ADDR_OFF) {
            s->dac_index = 0;
            return true;
        }
        if (reg == MGRAS_DAC_PAL_OFF) {
            s->dac_lut[0][s->dac_index] = (uint16_t)val;
            return true;
        }
        if (reg == MGRAS_DAC_CMD_OFF) {
            s->dac_ctrl[0] = (uint8_t)val;
            return true;
        }
        return false;
    }
    return false;
}



static void mgras_win_write_xmap(SGIMgrasWin *s, hwaddr off, uint64_t val)
{
    if (off == MGRAS_HQ_FLAG_USER_OFF) {
        s->hq_flag_user |= (uint32_t)val;
    } else if (off == MGRAS_HQ_FLAG_CLR_USER_OFF) {
        s->hq_flag_user &= ~(uint32_t)val;
    } else if (off == MGRAS_HQ_FLAG_PRIV_OFF) {
        s->hq_flag_priv |= (uint32_t)val;
    } else if (off == MGRAS_HQ_INTR_ENAB_OFF) {
        s->hq_intr_enab = (uint32_t)val;
    }
    if (off == MGRAS_XMAP_BASE + MGRAS_XMAP_INDEX_OFF) {
        s->xmap_index = (uint8_t)val;
    } else if (off == MGRAS_XMAP_BASE + MGRAS_XMAP_CONFIG_OFF) {
        s->xmap_config = (uint32_t)val;
    } else if (off == MGRAS_XMAP_BASE + MGRAS_XMAP_MAINMODE_OFF) {
        s->xmap_main_mode[0] = (uint32_t)val;
    } else if (off == MGRAS_XMAP_BASE + MGRAS_XMAP_OVLMODE_OFF) {
        s->xmap_ovl_mode[0] = (uint32_t)val;
    }
}

/* form 4: a switch on the widget offset itself -- the form a scan for `==`
 * misses.  One arm reads model state (`implemented`), one answers a constant
 * (`fixed`), so both halves of the classification are exercised. */
#define MGRAS_VC3_RAM_OFF        0x72190
#define MGRAS_VC3_INDEXDATA_OFF  0x72038
#define MGRAS_BDVERS0_OFF        0x72408

static bool mgras_win_read_switch(SGIMgrasWin *s, hwaddr off, uint64_t *v)
{
    switch (off) {
    case MGRAS_VC3_RAM_OFF:
        *v = s->vc3_sram[0];
        return true;
    case MGRAS_VC3_INDEXDATA_OFF:
        *v = s->vc3_indexdata;
        return true;
    case MGRAS_BDVERS0_OFF:
        return 0x2;                 /* a constant answer */
    }
    return false;
}
