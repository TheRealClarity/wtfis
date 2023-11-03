//
//  patchfinder64.c
//  kokeshidoll
//
//  Created by Vladimir Putin on 14.12.16.
//  Fixes by Alex Hude and Max Bazaliy
//  Updated by sakuRdev on 2021/12/02.
//  Some parts of code from Luca Todesco and Pangu
//
//  Copyright (c) 2016 -2017 FriedApple Team. All rights reserved.
//  Copyright (c) 2021 sakuRdev. All rights reserved.
//

#ifdef __LP64__

#include "patchfinder64.h"

static uint32_t* find_next_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction < (uintptr_t)kdata + ksize - 4) {
        current_instruction++;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

static uint32_t* find_prev_insn_matching_64(uint8_t* kdata, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    //just do it
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        current_instruction--;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

static int insn_is_cmp_64(uint32_t* i)
{
    /* 0x2100001F */
    if ((*i & 0x2100001F) == 0x2100001F)
        return 1;
    else
        return 0;
}

static int insn_is_cbnz_w32(uint32_t* i)
{
    return (*i >> 24 == 0x35);
}

static int insn_is_orr_w32(uint32_t* i)
{
    return (*i >> 24 == 0x32);
}

static int insn_is_ret(uint32_t* i)
{
    if (*i == 0xd65f03c0)
        return 1;
    
    return 0;
}

__unused static uint32_t bit_range_64(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

__unused static uint64_t real_signextend_64(uint64_t imm, uint8_t bit)
{
    if ((imm >> bit) & 1) {
        return (-1LL << (bit + 1)) + imm;
    } else
        return imm;
}

__unused static uint64_t signextend_64(uint64_t imm, uint8_t bit)
{
    assert(bit > 0);
    return real_signextend_64(imm, bit - 1);
    /*
     if ((imm >> bit) & 1)
     return (uint64_t)(-1) - (~((uint64_t)1 << bit)) + imm;
     else
     return imm;
     */
}

__unused static int insn_is_mov_reg64(uint32_t* i)
{
    return (*i & 0x7FE003E0) == 0x2A0003E0;
}

__unused static int insn_mov_reg_rt64(uint32_t* i)
{
    return (*i >> 16) & 0x1F;
}

__unused static int insn_mov_reg_rd64(uint32_t* i)
{
    return *i & 0x1F;
}

__unused static int insn_is_movz_64(uint32_t* i)
{
    return (*i & 0x7F800000) == 0x52800000;
}

__unused static int insn_movz_rd_64(uint32_t* i)
{
    return *i & 0x1F;
}

__unused static int insn_is_mov_imm_64(uint32_t* i)
{
    if ((*i & 0x7f800000) == 0x52800000)
        return 1;
    
    return 0;
}

static int insn_is_movz_x0_0(uint32_t *i)
{
    if(*i == 0xd2800000){
        return 1;
    }
    return 0;
}


__unused static int insn_mov_imm_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static uint32_t insn_mov_imm_imm_64(uint32_t* i)
{
    return bit_range_64(*i, 20, 5);
}

__unused static uint32_t insn_movz_imm_64(uint32_t* i)
{
    return bit_range_64(*i, 20, 5);
}

__unused static int insn_is_ldr_literal_64(uint32_t* i)
{
    // C6.2.84 LDR (literal) LDR Xt
    if ((*i & 0xff000000) == 0x58000000)
        return 1;
    
    // C6.2.84 LDR (literal) LDR Wt
    if ((*i & 0xff000000) == 0x18000000)
        return 1;
    
    // C6.2.95 LDR (literal) LDRSW Xt
    if ((*i & 0xff000000) == 0x98000000)
        return 1;
    
    return 0;
}

__unused static int insn_nop_64(uint32_t *i)
{
    return (*i == 0xD503201F);
}

__unused static int insn_add_reg_rm_64(uint32_t* i)
{
    return ((*i >> 16) & 0x1f);
}

__unused static int insn_ldr_literal_rt_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static uint64_t insn_ldr_literal_imm_64(uint32_t* i)
{
    uint64_t imm = (*i & 0xffffe0) >> 3;
    return signextend_64(imm, 21);
}

__unused static uint64_t insn_adr_imm_64(uint32_t* i)
{
    uint64_t immhi = bit_range_64(*i, 23, 5);
    uint64_t immlo = bit_range_64(*i, 30, 29);
    uint64_t imm = (immhi << 2) + (immlo);
    return signextend_64(imm, 19+2);
}

__unused static uint64_t insn_adrp_imm_64(uint32_t* i)
{
    uint64_t immhi = bit_range_64(*i, 23, 5);
    uint64_t immlo = bit_range_64(*i, 30, 29);
    uint64_t imm = (immhi << 14) + (immlo << 12);
    return signextend_64(imm, 19+2+12);
}

__unused static int insn_is_adrp_64(uint32_t* i)
{
    if ((*i & 0x9f000000) == 0x90000000) {
        return 1;
    }
    
    return 0;
}

__unused static int insn_adrp_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_mov_bitmask(uint32_t* i)
{
    return (*i & 0x7F8003E0) == 0x320003E0;
}

__unused static int insn_mov_bitmask_rd(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_add_imm_64(uint32_t* i)
{
    if ((*i & 0x7f000000) == 0x11000000)
        return 1;
    
    return 0;
}

__unused static int insn_add_imm_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_add_imm_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static uint64_t insn_add_imm_imm_64(uint32_t* i)
{
    uint64_t imm = bit_range_64(*i, 21, 10);
    if (((*i >> 22) & 3) == 1)
        imm = imm << 12;
    return imm;
}

__unused static int insn_add_reg_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_add_reg_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_is_add_reg_64(uint32_t* i)
{
    if ((*i & 0x7fe00c00) == 0x0b200000)
        return 1;
    
    return 0;
}

__unused static int insn_is_adr_64(uint32_t* i)
{
    if ((*i & 0x9f000000) == 0x10000000)
        return 1;
    
    return 0;
}

__unused static int insn_adr_rd_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_bl_64(uint32_t* i)
{
    if ((*i & 0xfc000000) == 0x94000000)
        return 1;
    else
        return 0;
}

__unused static int insn_is_strb(uint32_t* i)
{
    // TODO: more encodings
    return (*i >> 24 == 0x39);
}

__unused static int insn_rt_strb(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_rn_strb(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_strb_imm12(uint32_t* i)
{
    return ((*i >> 10) & 0xfff);
}

__unused static int insn_is_br_64(uint32_t *i)
{
    if ((*i & 0xfffffc1f) == 0xd61f0000)
        return 1;
    else
        return 0;
}

__unused static int insn_br_reg_xn_64(uint32_t *i)
{
    if ((*i & 0xfffffc1f) != 0xd61f0000)
        return 0;
    return (*i >> 5) & 0x1f;
}

__unused static uint64_t insn_bl_imm32_64(uint32_t* i)
{
    uint64_t imm = (*i & 0x3ffffff) << 2;
    //PFExtLog("imm = %llx\n", imm);
    // sign extend
    uint64_t res = real_signextend_64(imm, 27);
    
    //PFExtLog("real_signextend_64 = %llx\n", res);
    
    return res;
}

__unused static uint64_t insn_mov_bitmask_imm_64(uint32_t* i)
{
    // Extract the N, imms, and immr fields.
    uint32_t N = (*i >> 22) & 1;
    uint32_t immr = bit_range_64(*i, 21, 16);
    uint32_t imms = bit_range_64(*i, 15, 10);
    uint32_t j;
    
    int len = 31 - __builtin_clz((N << 6) | (~imms & 0x3f));
    
    uint32_t size = (1 << len);
    uint32_t R = immr & (size - 1);
    uint32_t S = imms & (size - 1);
    
    uint64_t pattern = (1ULL << (S + 1)) - 1;
    for (j = 0; j < R; ++j)
        pattern = ((pattern & 1) << (size-1)) | (pattern >> 1); // ror
    
    return pattern;
}

__unused int insn_is_funcbegin_64(uint32_t* i)
{
    if (*i == 0xa9bf7bfd)
        return 1;
    if (*i == 0xa9bc5ff8)
        return 1;
    if (*i == 0xa9bd57f6)
        return 1;
    if (*i == 0xa9ba6ffc)
        return 1;
    if (*i == 0xa9bb67fa)
        return 1;
    if (*i == 0xa9be4ff4)
        return 1;
    return 0;
}

__unused static int insn_is_tbz(uint32_t* i)
{
    return ((*i >> 24) & 0x7f) == 0x36;
}

__unused static int insn_is_tbnz(uint32_t* i)
{
    return ((*i >> 24) & 0x7f) == 0x37;
}

__unused static int insn_is_tbnz_w32(uint32_t* i)
{
    return (*i >> 24 == 0x37);
}

__unused static int insn_is_cbz_w32(uint32_t* i)
{
    return (*i >> 24 == 0x34);
}

__unused static int insn_is_cbz_x64(uint32_t* i)
{
    return (*i >> 24 == 0xb4);
}

__unused static int insn_is_cbz_64(uint32_t* i)
{
    return ((*i >> 24) & 0x7f) == 0x34;
}

__unused static int insn_is_mrs_from_TPIDR_EL1(uint32_t* i)
{
    // op0 op1  CRn  CRm op2
    //  11 000 1101 0000 100
    //
    return ((*i & 0xFFFFFFF0) == 0xD538D080);
}

// search back for memory with step 4 bytes
__unused static uint32_t * memmem_back_64(uint32_t *ptr1, uint64_t max_count, const uint8_t *ptr2, size_t num)
{
    for ( uint64_t i = 0; i < max_count >> 2; ++i ) {
        if ( !memcmp(ptr1, ptr2, num) )
            return ptr1;
        --ptr1;
    }
    return 0;
}

__unused static int insn_ldr_imm_rt_64(uint32_t* i)
{
    return (*i & 0x1f);
}

__unused static int insn_is_b_conditional_64(uint32_t* i)
{
    if ((*i & 0xff000010) == 0x54000000)
        return 1;
    else
        return 0;
}

__unused static int insn_is_b_unconditional_64(uint32_t* i)
{
    if ((*i & 0xfc000000) == 0x14000000)
        return 1;
    else
        return 0;
}

__unused static int insn_ldr_imm_rn_64(uint32_t* i)
{
    return ((*i >> 5) & 0x1f);
}

__unused static int insn_is_ldr_imm_64(uint32_t* i)
{
    // C6.2.83 LDR (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0xb8400400)
        return 1;
    // C6.2.83 LDR (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0xb8400c00)
        return 1;
    // C6.2.83 LDR (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0xb9400000)
        return 1;
    //------------------------------------//
    
    // C6.2.86 LDRB (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0x38400400)
        return 1;
    // C6.2.86 LDRB (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0x38400c00)
        return 1;
    // C6.2.86 LDRB (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0x39400000)
        return 1;
    //------------------------------------//
    
    // C6.2.90 LDRSB (immediate) Post-index
    if ((*i * 0xbfa00c00) == 0x38800400)
        return 1;
    // C6.2.90 LDRSB (immediate) Pre-index
    if ((*i * 0xbfa00c00) == 0x38800c00)
        return 1;
    // C6.2.90 LDRSB (immediate) Unsigned offset
    if ((*i * 0xbf800000) == 0x39800000)
        return 1;
    //------------------------------------//
    
    // C6.2.88 LDRH (immediate) Post-index
    if ((*i * 0xbfe00c00) == 0x78400c00)
        return 1;
    // C6.2.88 LDRH (immediate) Pre-index
    if ((*i * 0xbfe00c00) == 0x78400c00)
        return 1;
    // C6.2.88 LDRH (immediate) Unsigned offset
    if ((*i * 0xbfc00000) == 0x79400000)
        return 1;
    //------------------------------------//
    
    // C6.2.92 LDRSH (immediate) Post-index
    if ((*i * 0xbfa00c00) == 0x78800c00)
        return 1;
    // C6.2.92 LDRSH (immediate) Pre-index
    if ((*i * 0xbfa00c00) == 0x78800c00)
        return 1;
    // C6.2.92 LDRSH (immediate) Unsigned offset
    if ((*i * 0xbf800000) == 0x79800000)
        return 1;
    //------------------------------------//
    
    
    // C6.2.94 LDRSW (immediate) Post-index
    if ((*i * 0xbfe00c00) == 0xb8800400)
        return 1;
    // C6.2.94 LDRSW (immediate) Pre-index
    if ((*i * 0xbfe00c00) == 0xb8800c00)
        return 1;
    // C6.2.94 LDRSW (immediate) Unsigned offset
    if ((*i * 0xbfc00000) == 0xb9800000)
        return 1;
    
    return 0;
}

// TODO: other encodings
__unused static uint64_t insn_ldr_imm_imm_64(uint32_t* i)
{
    uint64_t imm;
    // C6.2.83 LDR (immediate) Post-index
    if ((*i & 0xbfe00c00) == 0xb8400400)
    {
        imm = bit_range_64(*i, 20, 12);
        return signextend_64(imm, 9);
    }
    
    // C6.2.83 LDR (immediate) Pre-index
    if ((*i & 0xbfe00c00) == 0xb8400c00)
    {
        imm = bit_range_64(*i, 20, 12);
        return signextend_64(imm, 9);
    }
    
    // C6.2.83 LDR (immediate) Unsigned offset
    if ((*i & 0xbfc00000) == 0xb9400000)
    {
        imm = bit_range_64(*i, 21, 10);
        if ((*i >> 30) & 1) // LDR X
            return imm * 8;
        else
            return imm * 4;
    }
    
    //PFLog("Warning! Unsupported encoding or not LDR instruction is passed!\n");
    
    return 0;
}

// calculate value (if possible) of register before specific instruction
static uint64_t find_pc_rel_value_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* last_insn, int reg)
{
    int found = 0;
    uint32_t* current_instruction = last_insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        current_instruction--;
        
        if(insn_is_mov_imm_64(current_instruction) && insn_mov_imm_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if(insn_is_ldr_literal_64(current_instruction) && insn_ldr_literal_rt_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if (insn_is_adrp_64(current_instruction) && insn_adrp_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if (insn_is_adr_64(current_instruction) && insn_adr_rd_64(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }
    if(!found)
        return 0;
    uint64_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)last_insn)
    {
        if(insn_is_mov_imm_64(current_instruction) && insn_mov_imm_rd_64(current_instruction) == reg)
        {
            value = insn_mov_imm_imm_64(current_instruction);
            //PFExtLog("%s:%d mov (immediate): value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if(insn_is_ldr_literal_64(current_instruction) && insn_ldr_literal_rt_64(current_instruction) == reg)
        {
            value = *(uint64_t*)((uintptr_t)current_instruction + insn_ldr_literal_imm_64(current_instruction));
            //PFExtLog("%s:%d ldr (literal): value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_ldr_imm_64(current_instruction) && insn_ldr_imm_rn_64(current_instruction) == reg)
        {
            value += insn_ldr_imm_imm_64(current_instruction);
            //PFExtLog("%s:%d ldr (immediate): value = %#llx\n", __func__, __LINE__, value);
        }
        if (insn_is_adrp_64(current_instruction) && insn_adrp_rd_64(current_instruction) == reg)
        {
            value = ((((uintptr_t)current_instruction - (uintptr_t)kdata) >> 12) << 12) + insn_adrp_imm_64(current_instruction);
            //PFExtLog("%s:%d adrp: value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_adr_64(current_instruction) && insn_adr_rd_64(current_instruction) == reg)
        {
            value = (uintptr_t)current_instruction - (uintptr_t)kdata + insn_adr_imm_64(current_instruction);
            //PFExtLog("%s:%d adr: value is reset to %#llx\n", __func__, __LINE__, value);
        }
        else if(insn_is_add_reg_64(current_instruction) && insn_add_reg_rd_64(current_instruction) == reg)
        {
            if (insn_add_reg_rm_64(current_instruction) != 15 || insn_add_reg_rn_64(current_instruction) != reg)
            {
                //PFExtLog("%s:%d add (register): unknown source register, value is reset to 0\n", __func__, __LINE__);
                return 0;
            }
            
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
            //PFExtLog("%s:%d add: PC register, value = %#llx\n", __func__, __LINE__, value);
        }
        else if (insn_is_add_imm_64(current_instruction) && insn_add_imm_rd_64(current_instruction) == reg)
        {
            if (insn_add_imm_rn_64(current_instruction) != reg)
            {
                //PFExtLog("%s:%d add (immediate): unknown source register, value is reset to 0\n", __func__, __LINE__);
                return 0;
            }
            value += insn_add_imm_imm_64(current_instruction);
            //PFExtLog("%s:%d add (immediate): value = %#llx\n", __func__, __LINE__, value);
        }
        
        current_instruction++;
    }
    //PFExtLog("%s:%d FINAL value = %#llx\n", __func__, __LINE__, value);
    
    return value;
}

static uint32_t* find_literal_ref_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* insn, uint64_t address)
{
    uint32_t* current_instruction = insn;
    uint64_t registers[32];
    memset(registers, 0, sizeof(registers));
    
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if (insn_is_mov_imm_64(current_instruction))
        {
            int reg = insn_mov_imm_rd_64(current_instruction);
            uint64_t value = insn_mov_imm_imm_64(current_instruction);
            registers[reg] = value;
            //PFExtLog("%s:%d mov (immediate): reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
        }
        else if (insn_is_ldr_literal_64(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)current_instruction + (uintptr_t)insn_ldr_literal_imm_64(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                int reg = insn_ldr_literal_rt_64(current_instruction);
                uint64_t value =  *(uint64_t*)(literal_address);
                registers[reg] = value;
                //PFExtLog("%s:%d ldr (literal): reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
            }
        }
        else if (insn_is_adrp_64(current_instruction))
        {
            int reg = insn_adrp_rd_64(current_instruction);
            uint64_t value = ((((uintptr_t)current_instruction - (uintptr_t)kdata) >> 12) << 12) + insn_adrp_imm_64(current_instruction);
            registers[reg] = value;
            //PFExtLog("%s:%d adrp: reg[%d] is reset to %#llx\n", __func__, __LINE__, reg, value);
        }
        else if (insn_is_adr_64(current_instruction))
        {
            uint64_t value = (uintptr_t)current_instruction - (uintptr_t)kdata + insn_adr_imm_64(current_instruction);
            if (value == address)
            {
                //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                return current_instruction;
            }
        }
        else if(insn_is_add_reg_64(current_instruction))
        {
            int reg = insn_add_reg_rd_64(current_instruction);
            if(insn_add_reg_rm_64(current_instruction) == 15 && insn_add_reg_rn_64(current_instruction) == reg)
            {
                uint64_t value = ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                registers[reg] += value;
                //PFExtLog("%s:%d adrp: reg[%d] += %#llx\n", __func__, __LINE__, reg, value);
                if(registers[reg] == address)
                {
                    //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                    return current_instruction;
                }
            }
        }
        else if (insn_is_add_imm_64(current_instruction))
        {
            int reg = insn_add_imm_rd_64(current_instruction);
            if (insn_add_imm_rn_64(current_instruction) == reg)
            {
                uint64_t value = insn_add_imm_imm_64(current_instruction);
                registers[reg] += value;
                //PFExtLog("%s:%d adrp: reg[%d] += %#llx\n", __func__, __LINE__, reg, value);
                if (registers[reg] == address)
                {
                    //PFExtLog("%s:%d FINAL pointer is %#llx\n", __func__, __LINE__, (uint64_t)current_instruction - (uint64_t)kdata);
                    return current_instruction;
                }
            }
            
        }
        
        current_instruction++;
    }
    
    //PFExtLog("%s:%d FINAL pointer is NULL\n", __func__, __LINE__);
    return NULL;
}

// search next instruction, decrementing mode
static uint32_t* find_last_insn_matching_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t* current_instruction, int (*match_func)(uint32_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        current_instruction--;
        
        if(match_func(current_instruction)) {
            return current_instruction;
        }
    }
    
    return NULL;
}

static uint64_t find_next_insn_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

static uint64_t find_next_next_insn_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

static uint64_t find_mac_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb, size_t sub)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_ret);
    if(!insn) return 0;
    
    uint64_t offset = (uint64_t)insn - (uintptr_t)kdata;
    offset -= sub;
    
    return offset;
}

uint64_t find_all_proc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // __text:FFFFFF800BB75E58 23 0A 00 90                 ADRP            X3, #aShutdownwait@PAGE ; "shutdownwait"
    // __text:FFFFFF800BB75E5C 63 48 04 91                 ADD             X3, X3, #aShutdownwait@PAGEOFF ; "shutdownwait"
    // __text:FFFFFF800BB75E60 DF BF FF 97                 BL              _msleep
    // __text:FFFFFF800BB75E64 FB 03 00 AA                 MOV             X27, X0
    // __text:FFFFFF800BB75E68 9B 05 00 34                 CBZ             W27, loc_FFFFFF800BB75F18
    // __text:FFFFFF800BB75E6C 48 AF 40 F9                 LDR             X8, [X26,#(all_proc - 0xFFFFFF800BD9E050)]
    //
    // __text:FFFFFF800245FD5C 83 0E 00 90                 ADRP            X3, #aShutdownwait@PAGE ; "shutdownwait"
    // __text:FFFFFF800245FD60 63 38 31 91                 ADD             X3, X3, #aShutdownwait@PAGEOFF ; "shutdownwait"
    // __text:FFFFFF800245FD64 E4 17 40 F9                 LDR             X4, [SP,#0xE0+var_B8]
    // __text:FFFFFF800245FD68 31 16 00 94                 BL              _msleep
    // __text:FFFFFF800245FD6C FB 03 00 AA                 MOV             X27, X0
    // __text:FFFFFF800245FD70 FB 06 00 34                 CBZ             W27, loc_FFFFFF800245FE4C
    // __text:FFFFFF800245FD74 C8 13 00 90                 ADRP            X8, #_allproc@PAGE
    // __text:FFFFFF800245FD78 08 0D 44 F9                 LDR             X8, [X8,#_allproc@PAGEOFF]
    uint8_t* str = memmem(kdata, ksize, "shutdownwait", sizeof("shutdownwait"));
    if(!str)
        return 0;
    
    // Find a reference to the string.
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)str - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    //PFLog("string ref %p\n", (void *)((uint8_t *)ref - kdata));
    
    // find BL
    uint32_t *bl_addr = find_next_insn_matching_64(region, kdata, ksize, ref, insn_is_bl_64);
    if (!bl_addr)
        return 0;
    
    //PFLog("bl_addr %p\n", (void *)((uint8_t *)bl_addr - kdata));
    
    // Find LDR
    uint32_t* ldr_addr = find_next_insn_matching_64(region, kdata, ksize, bl_addr, insn_is_ldr_imm_64);
    if (!ldr_addr)
        return 0;
    
    //PFLog("ldr_addr %p\n", (void *)((uint8_t *)ldr_addr - kdata));
    
    uint64_t pc_ref = find_pc_rel_value_64(region, kdata, ksize, ldr_addr, insn_ldr_imm_rn_64(ldr_addr));
    if (!pc_ref)
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr_addr + 1, insn_ldr_imm_rn_64(ldr_addr));
}

uint64_t find_ret0_gadget(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_x0_0_ret[] = { 0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, magic_x0_0_ret, sizeof(magic_x0_0_ret) / sizeof(*magic_x0_0_ret));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_ret1_gadget(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magic_w0_1_ret[] = { 0xE0, 0x03, 0x00, 0x32, 0xC0, 0x03, 0x5F, 0xD6 };
    
    // locate sequence
    uint8_t* magicSequencePtr = memmem(kdata, ksize, magic_w0_1_ret, sizeof(magic_w0_1_ret) / sizeof(*magic_w0_1_ret));
    if (!magicSequencePtr)
        return 0;
    
    return (uint64_t)(magicSequencePtr - kdata);
}

uint64_t find_memset(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint32_t opcode = 0xb200c3e3; // orr x3, xzr, #0x101010101010101
    uint32_t* orr = memmem(kdata, ksize, &opcode, sizeof(uint32_t));
    if(!orr)
        return 0;
    
    return (uintptr_t)orr - (uintptr_t)kdata - 0xc;
}

uint64_t find_GOT_address_with_bl_64(uint64_t region, uint8_t* kdata, size_t ksize, uint32_t *insn)
{
    // check if BL is specified
    if (!insn_is_bl_64(insn))
        return 0;
    
    // get address of GOT stub
    uint8_t* address = (uint8_t *)insn + insn_bl_imm32_64(insn);
    //PFLog("%s: address %p\n", __func__, (void *)(address - kdata + region));
    
    // find BR instruction
    uint32_t *instr = find_next_insn_matching_64(region, kdata, ksize, (uint32_t *)address, insn_is_br_64);
    if (!instr)
        return 0;
    //PFLog("%s: BR address %p\n", __func__, (void *)((uint8_t*)instr - kdata + region));
    
    // check if it's BR x16
    if (insn_br_reg_xn_64(instr) != 16)
        return 0;
    
    // get location of GOT - X16
    uint64_t GOT_address_value = find_pc_rel_value_64(region, kdata, ksize, instr, 16);
    if (!GOT_address_value)
        return 0;
    
    return GOT_address_value;
}

uint64_t find_sb_memset_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region)); // mpo_proc_check_fork
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

uint64_t find_sb_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    // _PE_i_can_has_debugger.stub
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

uint64_t find_sb_vfs_rootvnode_got(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

uint64_t find_rootvnode_offset(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t fn)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(fn-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_adrp_64);
    if(!insn) return 0;
    
    uint64_t value = ((((uintptr_t)insn - (uintptr_t)kdata) >> 12) << 12) + insn_adrp_imm_64(insn);
    insn += 1;
    value += insn_ldr_imm_imm_64(insn);
    
    return value;
}

uint64_t find_amfi_cs_enforcement_got(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "failed getting entitlements";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find 'BL _cs_enforcement.stub'
    uint32_t *bl_cs_enforcement = find_next_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_cs_enforcement)
        return 0;
    
    // get _cs_enforcement.stub address
    return find_GOT_address_with_bl_64(region, kdata, ksize, bl_cs_enforcement);
}

uint64_t find_amfi_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "failed getting entitlements";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find 'BL _cs_enforcement.stub'
    uint32_t *bl_cs_enforcement = find_next_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_bl_64);
    if (!bl_cs_enforcement)
        return 0;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    uint32_t *bl_PE_i_can_has_debugger = find_next_insn_matching_64(region, kdata, ksize, bl_cs_enforcement, insn_is_bl_64);
    if (!bl_PE_i_can_has_debugger)
        return 0;
    
    // get _PE_i_can_has_debugger.stub address
    return find_GOT_address_with_bl_64(region, kdata, ksize, bl_PE_i_can_has_debugger);
}

uint64_t find_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "AMFI: hook..execve() killing pid %u: %s";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find begining of function
    uint32_t *begin_execve_hook = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_funcbegin_64);
    if (!begin_execve_hook)
        return 0;
    //PFLog("%s: execve_hook %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)begin_execve_hook - kdata + region));
    
    // find 'BL vnode_isreg'
    uint32_t *bl_vnode_isreg = find_next_insn_matching_64(region, kdata, ksize, begin_execve_hook, insn_is_bl_64);
    if (!bl_vnode_isreg)
        return 0;
    
    // get bl_vnode_isreg address
    return (uintptr_t)bl_vnode_isreg - (uintptr_t)kdata + 4;
}

uint64_t find_vnode_isreg_in_amfi_execve_hook(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "AMFI: hook..execve() killing pid %u: %s";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find begining of function
    uint32_t *begin_execve_hook = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_funcbegin_64);
    if (!begin_execve_hook)
        return 0;
    //PFLog("%s: execve_hook %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)begin_execve_hook - kdata + region));
    
    // find 'BL vnode_isreg'
    uint32_t *bl_vnode_isreg = find_next_insn_matching_64(region, kdata, ksize, begin_execve_hook, insn_is_bl_64);
    if (!bl_vnode_isreg)
        return 0;
    
    // get bl_vnode_isreg address
    return find_GOT_address_with_bl_64(region, kdata, ksize, bl_vnode_isreg);
}

uint64_t find_LwVM_PE_i_can_has_debugger_got(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char magicStr[] = "_mapForIO";
    void *_mapForIO_Str = memmem(kdata, ksize, magicStr, sizeof(magicStr) / sizeof(*magicStr));
    if (!_mapForIO_Str)
        return 0;
    
    // Find a reference to the _mapForIO string.
    uint32_t* ptr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)_mapForIO_Str - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // find begin of _mapForIO
    uint32_t *_mapForIOfunc = find_last_insn_matching_64(region, kdata, ksize, ptr, insn_is_funcbegin_64);
    if (!_mapForIOfunc)
        return 0;
    
    //PFLog("_mapForIO %#lx\n", (uint8_t *)_mapForIOfunc - kdata);
    
    uint32_t *insn = _mapForIOfunc;
    while (1) {
        insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
        if (!insn)
            return 0;
        
        if (insn_is_tbnz(insn + 1))
            break;
    }
    
    insn = find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_movz_x0_0);
    if (!insn)
        return 0;
    
    insn += 1;
    
    /*
     *     movz       x0, #0x0
     *     bl         _PE_i_can_has_debugger.stub // -> canMap
     *     cbz        w0, fail
     *
     * check:
     *     cmp        w27, #0x2
     *     b.ne       canMap
     *
     *     tbnz       w26, 0x0, canMap
     *
     *     ldr        x8, [x20, #0x1a0]
     *     ldrb       w8, [x8, #0x28]
     *     cbz        w8, canMap
     */
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

uint64_t find_PE_i_can_has_kernel_configuration_got(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // string from LightweightVolumeManager::_mapForIO
    const char magicStr[] = "_mapForIO";
    
    void *_mapForIO_Str = memmem(kdata, ksize, magicStr, sizeof(magicStr) / sizeof(*magicStr));
    if (!_mapForIO_Str)
        return 0;
    
    // Find a reference to the _mapForIO string.
    uint32_t* ptr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)_mapForIO_Str - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // find begin of _mapForIO
    uint32_t *_mapForIOfunc = find_last_insn_matching_64(region, kdata, ksize, ptr, insn_is_funcbegin_64);
    if (!_mapForIOfunc)
        return 0;
    
    //PFLog("_mapForIO %#lx\n", (uint8_t *)_mapForIOfunc - kdata);
    
    uint32_t *insn = _mapForIOfunc;
    while (1) {
        insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
        if (!insn)
            return 0;
        
        if (insn_is_tbz(insn + 1))
            break;
    }
    
    //PFLog("bl PE_i_can_has_kernel_configuration %#lx\n", (uint8_t *)insn - kdata);
    
    /*
     *     bl         _PE_i_can_has_kernel_configration.stub // -> canMap
     *     tbz        w0, 0x0, fail
     *
     * check:
     *     cmp        w27, #0x2
     *     b.ne       canMap
     *
     *     tbnz       w26, 0x0, canMap
     *
     *     ldr        x8, [x20, #0x1a0]
     *     ldrb       w8, [x8, #0x28]
     *     cbz        w8, canMap
     */
    
    
    return find_GOT_address_with_bl_64(region, kdata, ksize, insn);
}

static uint64_t find_cbz_addr(uint64_t src, uint32_t* i)
{
    uint32_t opcode = *i & ~0xFF00001F;
    
    if((opcode & 0x800000) == 0){
        uint32_t addr = opcode >> 3;
        return (src + addr);
    } else {
        opcode = ~opcode;
        opcode = opcode & ~0xFF00000F;
        uint32_t addr = opcode >> 2;
        return (src - addr);
    }
    
    return 0;
}

uint64_t find_lwvm_jump(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t magicCode[] = { 0x88, 0xD2, 0x40, 0xF9, 0x08, 0xA1, 0x40, 0x39 };
    uint32_t *ptr = memmem(kdata, ksize, magicCode, sizeof(magicCode) / sizeof(*magicCode));
    if (!ptr)
        return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, ptr, insn_is_cbz_w32);
    
    uint64_t src = ((uint64_t)insn - (uint64_t)kdata);
    uint64_t addr = find_cbz_addr(src, insn);
    if (!addr)
        return 0;
    
    return addr;
}

// find sandbox policy list
uint64_t find_sandbox_mac_policy_ops(uint64_t region, uint8_t* kdata, size_t ksize)
{
    char magicStr[] = "Seatbelt sandbox policy";
    
    // find `seatbelt` string
    uint32_t* magicStringPtr = memmem(kdata, ksize, magicStr, sizeof(magicStr) / sizeof(*magicStr));
    if (!magicStringPtr)
        return 0;
    
    uint64_t strAddress = (uintptr_t)magicStringPtr - (uintptr_t)kdata + region;
    uint64_t* ref = memmem(kdata, ksize, &strAddress, sizeof(strAddress));
    if (!ref)
        return 0;
    
    uint64_t sandbox_mac_policy_ops_ptr = *(ref + 3);
    return sandbox_mac_policy_ops_ptr - region;
}

uint64_t find_file_check_mmap_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_file_check_mmap_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_unlink_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x18);
}

uint64_t find_vnode_check_unlink_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_cmp_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

uint64_t find_vnode_check_unlink_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_truncate_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_truncate_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_stat_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_stat_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_setutimes_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_setutimes_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_setowner_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_setowner_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_setmode_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x18);
}

uint64_t find_vnode_check_setmode_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    /*
     * -> find strb
     * ffffff8004fddde8  bl    _memset.stub
     * ffffff8004fdddec  orr   w8, wzr, #0x1   <- lr
     * ffffff8004fdddf0  strb  w8, [sp, #0x8]  <- this
     *
     */
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_strb);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata - 4;
}

uint64_t find_vnode_check_setflags_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_setflags_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_setextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_setextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_setattrlist_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_setattrlist_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_revoke_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_revoke_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_readlink_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_readlink_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_open_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_open_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_listextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_listextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_link_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x1c);
}

uint64_t find_vnode_check_link_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint64_t lr2 = find_vnode_check_link_lr_2(region, kdata, ksize, sb);
    if(!lr2) return 0;
    
    uint32_t* fn_start = (uint32_t*)(kdata+lr2);
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_adr_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_adr_64); // "forbidden-link-priv"
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata;
}

uint64_t find_vnode_check_link_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_cbnz_w32);
    if(!insn) return 0;
    
    /*
     * -> find strb
     * ffffff8004fdd7bc  bl    _memset.stub
     * ffffff8004fdd7c0  strb  w25, [sp]        <- this
     * ffffff8004fdd7c4  str   w25, [sp, #0x58]
     *
     */
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_strb);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata;
}


uint64_t find_vnode_check_link_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_ioctl_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_ioctl_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_getextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_getextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_getattrlist_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_getattrlist_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_exchangedata_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_exchangedata_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_bl_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

uint64_t find_vnode_check_exchangedata_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_deleteextattr_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_deleteextattr_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_create_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_create_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint64_t lr3 = find_vnode_check_create_lr_3(region, kdata, ksize, sb);
    if(!lr3) return 0;
    
    uint32_t* fn_start = (uint32_t*)(kdata+lr3);
    if(!fn_start) return 0;
    
    // "forbidden-file-create-unsupported"
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_adr_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata;
}

uint64_t find_vnode_check_create_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint64_t lr3 = find_vnode_check_create_lr_3(region, kdata, ksize, sb);
    if(!lr3) return 0;
    
    uint32_t* fn_start = (uint32_t*)(kdata+lr3);
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_strb);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata - 4;
}


uint64_t find_vnode_check_create_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    // "forbidden-file-create-unknown"
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_adr_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata;
}

uint64_t find_vnode_check_chroot_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_vnode_check_chroot_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_access_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x14);
}

uint64_t find_vnode_check_access_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_vnode_check_rename_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x18);
}

uint64_t find_vnode_check_rename_lr_1(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint64_t lr2 = find_vnode_check_rename_lr_2(region, kdata, ksize, sb);
    if(!lr2) return 0;
    
    uint32_t* fn_start = (uint32_t*)(kdata+lr2);
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_cbnz_w32);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}


uint64_t find_vnode_check_rename_lr_2(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_cbz_x64);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

uint64_t find_vnode_check_rename_lr_3(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    uint32_t* fn_start = (uint32_t*)(kdata+(sb-region));
    if(!fn_start) return 0;
    
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, fn_start, insn_is_cbnz_w32);
    if(!insn) return 0;
    
    insn = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_bl_64);
    if(!insn) return 0;
    
    return (uint64_t)insn - (uintptr_t)kdata + 4;
}

uint64_t find_vnode_check_rename_lr_4(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_mount_check_fsctl_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_mount_check_fsctl_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_iokit_check_open_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_iokit_check_open_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}

uint64_t find_proc_check_fork_ret(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_mac_ret(region, kdata, ksize, sb, 0x10);
}

uint64_t find_proc_check_fork_lr(uint64_t region, uint8_t* kdata, size_t ksize, uint64_t sb)
{
    return find_next_insn_bl_64(region, kdata, ksize, sb);
}




// KPP
// This points to kernel_pmap. Use that to change the page tables if necessary.
uint64_t find_pmap_location(uint64_t region, uint8_t *kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd)
        return 0;
    
    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint32_t* ptr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr)
        return 0;
    
    // Find the end of it.
    const uint8_t search_function_end[] = { 0xC0, 0x03, 0x5F, 0xD6 }; // RET
    // iOS 9.x dirty fix ^_^
    --ptr; --ptr;
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr)
        return 0;
    
    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint32_t* bl = find_last_insn_matching_64(region, kdata, ksize, ptr, insn_is_bl_64);
    if (!bl)
        return 0;
    
    uint32_t *insn = 0;
    uint32_t *current_instruction = bl;
    while ( (uintptr_t)current_instruction > (uintptr_t)kdata ) {
        --current_instruction;
        if ( insn_is_ldr_imm_64(current_instruction) ) {
            if ( insn_ldr_imm_rt_64(current_instruction) == 2 ) {
                insn = current_instruction;
                break;
            }
        }
        if ( !insn_is_b_conditional_64(current_instruction) ) {
            if ( !insn_is_b_unconditional_64(current_instruction) )
                continue;
        }
        break;
    }
    if (!insn)
        return 0;
    uint64_t pc_rel = find_pc_rel_value_64(region, kdata, ksize, insn + 1, insn_ldr_imm_rn_64(insn));
    return pc_rel;
}

// CPACR
uint64_t find_cpacr_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "MSR CPACR_EL1, X0" instruction
    uint8_t CPACR_EL1[] = { 0x40, 0x10, 0x18, 0xD5 };
    uint8_t* insn = memmem(kdata, ksize, CPACR_EL1, sizeof(CPACR_EL1) / sizeof(*CPACR_EL1));
    if (!insn)
        return 0;
    
    return (uint64_t)(insn - kdata);
}

uint32_t *find_msr_ttbr0_el1_msr_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "MSR TTBR0_EL1, X0" and "MSR TTBR1_EL1, X1" instruction
    uint8_t MSR_TTBR0_EL1_MSR_TTBR0_EL1[] = { 0x00, 0x20, 0x18, 0xD5, 0x21, 0x20, 0x18, 0xD5 };
    uint32_t* insn = memmem(kdata, ksize, MSR_TTBR0_EL1_MSR_TTBR0_EL1, sizeof(MSR_TTBR0_EL1_MSR_TTBR0_EL1) / sizeof(*MSR_TTBR0_EL1_MSR_TTBR0_EL1));
    if (!insn)
        return 0;
    
    return insn;
}

// TTBRMAGIC_BX0
uint64_t find_arm_init_tramp(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint32_t *insn_init_tramp = find_msr_ttbr0_el1_msr_ttbr1_el1(region, kdata, ksize);
    if (!insn_init_tramp)
        return 0;
    
    uint32_t *insn = 0;
    if (!insn_is_ldr_imm_64(insn_init_tramp - 1)) {
        // try iOS 9.x
        
        // x0 = x25 + 0x4000
        // x1 = x25 + 0x5000
        // 6 9.3.4, 5s 9.3.5
        uint8_t loadData[] = { 0x20, 0x13, 0x40, 0x91, 0x01, 0x04, 0x40, 0x91 };
        // x0 = x25 + 0x10000
        // x1 = x25 + 0x14000
        // 6s 9.3.5
        uint8_t loadData2[] = { 0x20, 0x43, 0x40, 0x91, 0x01, 0x10, 0x40, 0x91 };
        
        insn = insn_init_tramp  - 2;
        
        // check first instructions
        if (memcmp(insn, loadData, sizeof(loadData) / sizeof(*loadData)))
            if (memcmp(insn, loadData2, sizeof(loadData2) / sizeof(*loadData2)))
                return 0;
    } else {
        // iOS 10.x
        
        // find adrp x1, TTBR1_EL1
        insn = find_next_insn_matching_64(region, kdata, ksize, insn_init_tramp - 6, insn_is_adrp_64);
        
        // find adrp x0, TTBR0_EL1
        insn = find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_adrp_64);
        if (!insn)
            return 0;
    }
    
    return (uint64_t)((uint8_t *)insn - kdata);
}

// TTBR1, on dumps only!
uint64_t find_ttbr1_el1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _arm_init_tramp_offset = find_arm_init_tramp(region, kdata, ksize);
    if (!_arm_init_tramp_offset)
        return 0;
    
    uint32_t *_arm_init_tramp = (uint32_t *)(kdata + _arm_init_tramp_offset);
    
    // find adrp x1, TTBR1_EL1
    uint32_t *insn = find_next_insn_matching_64(region, kdata, ksize, _arm_init_tramp, insn_is_adrp_64);
    if (!insn || (insn - _arm_init_tramp > 6)) {
        // try iOS 9.x
        
        // read from PMAP
        uint64_t pmap = find_pmap_location(region, kdata, ksize);
        if (!pmap)
            return 0;
        
        // read offset of pmap_store
        uint64_t kernel_pmap = *(uint64_t *)(kdata + pmap);
        if (!kernel_pmap)
            return 0;
        
        return kernel_pmap - region + 8;
    }
    else {
        // iOS 10.x
        //PFLog("iOS 10.x case\n");
        
        // get X1
        return find_pc_rel_value_64(region, kdata, ksize, _arm_init_tramp + 6, 1);
    }
}

static uint64_t find_ptd_alloc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char magicString[] = "\"out of ptd entry\\n\"";
    uint8_t* string = memmem(kdata, ksize, magicString, sizeof(magicString) - 1);
    if (!string)
        return 0;
    
    //PFLog("string offset %p\n", (void *)(string - kdata));
    
    uint32_t* ref = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)string - (uintptr_t)kdata);
    if (!ref)
        return 0;
    
    //PFLog("ref offset %p\n", (void *)((uint8_t*)ref - kdata));
    
    uint32_t *_ptd_alloc_offset = find_last_insn_matching_64(region, kdata, ksize, ref, insn_is_funcbegin_64);
    if (!_ptd_alloc_offset)
        return 0;
    
    //PFLog("_ptd_alloc offset %p\n", (void *)((uint8_t*)_ptd_alloc_offset - kdata));
    
    // locate sequence
    // ADRP            X9, #_gPhysBase@PAGE
    // LDR             X9, [X9,#_gPhysBase@PAGEOFF]
    // SUB             X8, X8, X9
    // ADRP            X9, #_gVirtBase@PAGE
    // LDR             X9, [X9,#_gVirtBase@PAGEOFF]
    // ADD             X23, X8, X9
    // MRS             X8, TPIDR_EL1
    
    uint32_t* mrs_instr = find_next_insn_matching_64(region, kdata, ksize, _ptd_alloc_offset, insn_is_mrs_from_TPIDR_EL1);
    if (!mrs_instr)
        return 0;
    
    // we need second occurance
    mrs_instr = find_next_insn_matching_64(region, kdata, ksize, mrs_instr + 1, insn_is_mrs_from_TPIDR_EL1);
    if (!mrs_instr)
        return 0;
    
    //PFLog("mrs Xy, TPIDR_EL1 %p\n", mrs_instr);
    
    return (uintptr_t)mrs_instr - (uintptr_t)kdata;
}

uint64_t find_gPhysAddr(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _ptd_alloc_offset = find_ptd_alloc(region, kdata, ksize);
    if (!_ptd_alloc_offset)
        return 0;
    
    uint32_t* _ptd_alloc_ptr = (uint32_t *)(kdata + _ptd_alloc_offset);
    
    // get ADRP _gPhysBase
    uint32_t* adrp = _ptd_alloc_ptr - 6;
    
    if (!insn_is_adrp_64(adrp))
        return 0;
    
    //PFLog("adrp offset %p\n", (void *)((uint8_t *)_ptd_alloc_ptr - kdata));
    
    uint32_t* ldr = adrp + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        return 0;
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_gVirtAddr(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t _ptd_alloc_offset = find_ptd_alloc(region, kdata, ksize);
    if (!_ptd_alloc_offset)
        return 0;
    
    uint32_t* _ptd_alloc_ptr = (uint32_t *)(kdata + _ptd_alloc_offset);
    
    // get ADRP _gVirtBase
    uint32_t* adrp = _ptd_alloc_ptr - 3;
    
    if (!insn_is_adrp_64(adrp))
        return 0;
    
    //PFLog("adrp offset %p\n", (void *)((uint8_t *)_ptd_alloc_ptr - kdata));
    
    uint32_t* ldr = adrp + 1;
    if (!insn_is_ldr_imm_64(ldr)) {
        return 0;
    }
    
    //PFLog("ldr offset %p\n", (void *)((uint8_t *)ldr - kdata));
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr + 1, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_PE_i_can_has_debugger(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // find "STR W8, X0 // B PC+4 // STR WZR, [X0]"
    uint8_t magic[] = { 0x08, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x14, 0x1F, 0x00, 0x00, 0xB9 };
    uint32_t* insn = memmem(kdata, ksize, magic, sizeof(magic) / sizeof(*magic));
    if (!insn) {
        return 0;
    }
    
    uint8_t *func_begin = (uint8_t *)find_last_insn_matching_64(region, kdata, ksize, insn, insn_is_cbz_x64);
    if (!func_begin)
        return 0;
    
    return (uint64_t)(func_begin - kdata);
}

uint64_t find_debug_enabled(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t is_enabled_func = find_PE_i_can_has_debugger(region, kdata, ksize);
    if (!is_enabled_func)
        return 0;
    
    // convert to pointer
    uint32_t* insn = (uint32_t *)(kdata + is_enabled_func);
    
    // get adrp
    uint32_t* ldr = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_ldr_literal_64);
    if (!ldr)
        return 0;
    
    uintptr_t literal_address  = (uintptr_t)ldr + (uintptr_t)insn_ldr_literal_imm_64(ldr);
    uint64_t _debug_enabled = literal_address - (uintptr_t)kdata;
    return _debug_enabled;
}

// return amfi_allow_any_signature address (allowInvalidSignatures)
// use +1 for amfi_get_out_of_my_way (allowEverything)
// use +2 for cs_enforcement_disable (csEnforcementDisable)
// use +3 for library validation (lvEnforceThirdParty)
uint64_t find_amfi_allow_any_signature(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char allowSignature[] = "%s: signature enforcement disabled by boot-arg\n";
    
    uint8_t *allowSignature_offset = memmem(kdata, ksize, allowSignature, sizeof(allowSignature) / sizeof(*allowSignature));
    if (!allowSignature_offset)
        return 0;
    
    //PFLog("allowSignature_offset %#lx\n", allowSignature_offset - kdata);
    
    // Find a reference to the string.
    uint32_t* insn = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)allowSignature_offset - (uintptr_t)kdata);
    if (!insn)
        return 0;
    
    uint32_t *strb_amfi_allow_any = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_strb);
    if (!strb_amfi_allow_any)
        return 0;
    
    // ADRP X22, #amfi_allow_any_signature@PAGE
    // ...
    // STRB W8, [X22,#amfi_allow_any_signature@PAGEOFF]
    // 1. find base
    uint64_t base_address = find_pc_rel_value_64(region, kdata, ksize, strb_amfi_allow_any, insn_rn_strb(strb_amfi_allow_any));
    // 2. extract offset from STRB
    return base_address + insn_strb_imm12(strb_amfi_allow_any);
}

uint64_t find_ml_get_wake_timebase(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t SLEEP[] = { 0x9F, 0x3F, 0x03, 0xD5, 0xDF, 0x3F, 0x03, 0xD5, 0x7F, 0x20, 0x03, 0xD5 };
    uint32_t* insn = memmem(kdata, ksize, SLEEP, sizeof(SLEEP) / sizeof(*SLEEP));
    if (!insn)
        return 0;
    
    uint64_t address = ((uint8_t *)insn - kdata) + 0x10;
    return address;
}

uint64_t find_amfi_ret(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t amfi_ret[] = { 0x00, 0x00, 0x80, 0x52, 0x08, 0x01, 0x09, 0x32, 0x08, 0x03, 0x00, 0xB9 };
    uint32_t* insn = memmem(kdata, ksize, amfi_ret, 12);
    if (!insn)
        return 0;
    
    uint64_t address = ((uint8_t *)insn - kdata) + 12;
    return address;
}

// __mac_mount patch address
uint64_t find_mac_mount_patch(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // iOS 9.3.2, 9.3.3, 9.3.5
    uint8_t __mac_mount_9x[] =  { 0x48, 0x04, 0x30, 0x36, 0x14, 0x04, 0x00, 0x37 };
    uint8_t __mac_mount_10x[] = { 0x68, 0x05, 0x30, 0x36, 0x34, 0x05, 0x00, 0x37 };
    uint8_t __mac_mount_8x[] = {
        0x9F, 0x02, 0x1B, 0x72, 0x88, 0x7A, 0x0F, 0x12,
        0x89, 0x02, 0x10, 0x32, 0x34, 0x01, 0x88, 0x1A
    };
    
    uint8_t *insn = memmem(kdata, ksize, __mac_mount_9x, sizeof(__mac_mount_9x) / sizeof(*__mac_mount_9x));
    if (!insn) {
        // try iOS 10x case
        uint8_t *insn = memmem(kdata, ksize, __mac_mount_10x, sizeof(__mac_mount_10x) / sizeof(*__mac_mount_10x));
        if (!insn) {
            // try iOS 8x case
            size_t size = sizeof(__mac_mount_8x) / sizeof(*__mac_mount_8x);
            uint8_t *insn = memmem(kdata, ksize, __mac_mount_8x, size);
            if (!insn)
                return 0;
            return (insn + size - kdata);
        }
    }
    
    return (insn + 4 - kdata);
}

uint64_t find_task_for_pid(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // 9.3.3, n51
    uint8_t search[] = { 0x00, 0x01, 0x40, 0xB9, 0x15, 0x09, 0x40, 0xB9, 0x13, 0x09, 0x40, 0xF9, 0xFF, 0x17, 0x00, 0xF9, 0xFF, 0x27, 0x00, 0xB9 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata) + 0x14;
    return address;
}

//yalu

uint64_t find_add_x0_232(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search: _buf_attr (or: 00a00391c0035fd6)
    // 0x9103a000: ADD      X0, X0, #232
    // 0xd65f03c0: RET
    uint8_t search[] = { 0x00, 0xA0, 0x03, 0x91, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_ldr_x0_x1_32(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search: 201040f9c0035fd6
    // 0xf9401020: LDR      X0, [X1,#0x20]
    // 0xd65f03c0: RET
    uint8_t search[] = { 0x20, 0x10, 0x40, 0xF9, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_str_w3_x1_w2_utxw(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search: 234822b8c0035fd6
    // 0xb8224823: STR      W3, [X1,W2,UXTW]
    // 0xd65f03c0: RET
    uint8_t search[] = { 0x23, 0x48, 0x22, 0xB8, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_invalidate_tlb(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search: 1f8708d59f3b03d5df3f03d5c0035fd6
    // 0xd508871f: TLBI
    // 0xd5033b9f: DSB      ISH
    // 0xd5033fdf: ISB
    // 0xd65f03c0: RET
    uint8_t search[] = { 0x1F, 0x87, 0x08, 0xD5, 0x9F, 0x3B, 0x03, 0xD5, 0xDF, 0x3F, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_flushcache(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search _flush_dcache (or: 9f3f03d5c0035fd6)
    // 0xd5033f9f: DSB      SY
    // 0xd65f03c0: RET
    uint8_t search[] = { 0x9F, 0x3F, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_add_x0_x0_0x40(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search: 00000191C0035FD6
    // FFFFFF8002B1341C                 ADD             X0, X0, #0x40
    // FFFFFF8002B13420                 RET
    uint8_t search[] = { 0x00, 0x00, 0x01, 0x91, 0xC0, 0x03, 0x5F, 0xD6 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

//check this on older versions
uint64_t find_mount_common(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 89 02 10 32 34 01 88 1A
    // ORR             W9, W20, #0x10000
    // CSEL            W20, W9, W8, EQ
    // add 0x8 to address
    uint8_t search[] = { 0x89, 0x02, 0x10, 0x32, 0x34, 0x01, 0x88, 0x1A };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address + 0x8;
}

//copy of find_amfi_allow_any_signature, improved for 8
// use -1 for amfi_get_out_of_my_way (allowEverything)
// use ret for cs_enforcement_disable (csEnforcementDisable)
// use +1 for library validation (lvEnforceThirdParty)
uint64_t find_cs_enforcement_disable(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char allowSignature[] = "%s: cs_enforcement disabled by boot-arg\n";
    
    uint8_t *allowSignature_offset = memmem(kdata, ksize, allowSignature, sizeof(allowSignature) / sizeof(*allowSignature));
    if (!allowSignature_offset)
        return 0;
    
    //PFLog("allowSignature_offset %#lx\n", allowSignature_offset - kdata);
    
    // Find a reference to the string.
    uint32_t* insn = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)allowSignature_offset - (uintptr_t)kdata);
    if (!insn)
        return 0;
    
    uint32_t *strb_amfi_allow_any = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_strb);
    if (!strb_amfi_allow_any)
        return 0;
    
    // ADRP X22, #amfi_allow_any_signature@PAGE
    // ...
    // STRB W8, [X22,#amfi_allow_any_signature@PAGEOFF]
    // 1. find base
    uint64_t base_address = find_pc_rel_value_64(region, kdata, ksize, strb_amfi_allow_any, insn_rn_strb(strb_amfi_allow_any));
    // 2. extract offset from STRB
    return base_address + insn_strb_imm12(strb_amfi_allow_any);
}

uint64_t find_vm_fault_enter(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 09 00 80 52 8A D0 38 D5
    //MOV             W9, #0
    //MRS             X10, #0, c13, c0, #4
    uint8_t search[] = { 0x09, 0x00, 0x80, 0x52, 0x8A, 0xD0, 0x38, 0xD5 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find next TBNZ
    uint8_t *tbnz = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_tbnz_w32);
    return (uint64_t)(tbnz - kdata);
}

uint64_t find_vm_map_enter(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 0A 79 1D 12
    //AND             W10, W8, #0xFFFFFFFB
    uint8_t search[] = { 0x0A, 0x79, 0x1D, 0x12 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_vm_map_protect(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 76 11 96 1A
    //CSEL            W22, W11, W22, NE
    uint8_t search[] = { 0x76, 0x11, 0x96, 0x1A };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    return address;
}

uint64_t find_cs_ops_1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 29 9C 81 52
    //MOV             W9, #0xCE1
    uint8_t search[] = { 0x29, 0x9C, 0x81, 0x52 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find next orr
    uint32_t *orr = (uint32_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_orr_w32);
    
    //... we should actually look for the orr after the previous one...
    uint8_t *sec_orr = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, orr, insn_is_orr_w32);
    return (uint64_t)(sec_orr - kdata);
}

uint64_t find_tfp0(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search FD C3 00 91 FF C3 00 D1 E8 03 00 AA
    //ADD             X29, SP, #0x30
    //SUB             SP, SP, #0x30
    //MOV             X8, X0
    uint8_t search[] = { 0xFD, 0xC3, 0x00, 0x91, 0xFF, 0xC3, 0x00, 0xD1, 0xE8, 0x03, 0x00, 0xAA };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find next cbz
    uint8_t *cbz = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_cbz_w32);
    return (uint64_t)(cbz - kdata);
}

uint64_t find_ICHDB_1(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t ichdb_func = find_PE_i_can_has_debugger(region, kdata, ksize);
    if (!ichdb_func)
        return 0;
    
    // convert to pointer
    uint32_t* insn = (uint32_t *)(kdata + ichdb_func);
    
    // get next cbz
    uint8_t * cbz = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_cbz_w32);
    return (uint64_t)(cbz - kdata);
}

uint64_t find_ICHDB_2(uint64_t region, uint8_t* kdata, size_t ksize)
{
    uint64_t ichdb_func = find_PE_i_can_has_debugger(region, kdata, ksize);
    if (!ichdb_func)
        return 0;
    
    // convert to pointer
    uint32_t* insn = (uint32_t *)(kdata + ichdb_func);
    
    // get next ret
    uint8_t * ret = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_ret);
    if (!ret)
        return 0;
    
    return (uint64_t)(ret - kdata - 4);
}

uint64_t find_mapIO(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 00 00 BC 52 40 58 80 72 00 08 00 11
    //MOV             W0, #0xE0000000
    //MOVK            W0, #0x2C2
    //ADD             W0, W0, #2
    uint8_t search[] = { 0x00, 0x00, 0xBC, 0x52, 0x40, 0x58, 0x80, 0x72, 0x00, 0x08, 0x00, 0x11 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find next branch
    uint8_t *b = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_b_unconditional_64);
    return (uint64_t)(b - kdata);
}

uint64_t find_sbtrace(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search FD 03 00 91 00 00 80 D2
    //MOV             X29, SP
    //MOV             X0, #0
    uint8_t search[] = { 0xFD, 0x03, 0x00, 0x91, 0x00, 0x00, 0x80, 0xD2 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    uint64_t address = ((uint8_t *)insn - kdata);
    //search again since it's the second match
    uint32_t* real_insn = memmem(kdata + address + 4, ksize - address - 4, search, sizeof(search) / sizeof(*search));
    //find next branch
    uint8_t *bl = (uint8_t *)find_next_insn_matching_64(region, kdata + address + 4, ksize - address - 4, real_insn, insn_is_bl_64);
    return (uint64_t)(bl - kdata);
}

uint64_t find_sbevaluate(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 1F 01 13 EB A4 1A 40 FA
    //CMP             X8, X19
    //CCMP            X21, #0, #4, NE
    uint8_t search[] = { 0x1F, 0x01, 0x13, 0xEB, 0xA4, 0x1A, 0x40, 0xFA };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find first ret behind
    uint8_t *ret = (uint8_t *)find_prev_insn_matching_64(kdata, insn, insn_is_ret);
    return (uint64_t)(ret - kdata + 4);
}

uint64_t find_vn_getpath(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char vngetpath[] = "vn_getpath() failed";
    
    uint8_t *vngetpath_offset = memmem(kdata, ksize, vngetpath, sizeof(vngetpath) / sizeof(*vngetpath));
    if (!vngetpath_offset)
        return 0;
    
    // Find a reference to the string.
    uint32_t* insn = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, (uintptr_t)vngetpath_offset - (uintptr_t)kdata);
    if (!insn)
        return 0;
    
    uint8_t *ICHDB_bl = (uint8_t *)find_prev_insn_matching_64(kdata, insn, insn_is_bl_64);
    
    if (!ICHDB_bl)
        return 0;
    
    uint8_t *vngetpath_bl = (uint8_t *)find_prev_insn_matching_64(kdata, (uint32_t*)ICHDB_bl, insn_is_bl_64);
    
    if (!vngetpath_bl)
        return 0;
    
    uint64_t vngetpath_func = find_GOT_address_with_bl_64(region, kdata, ksize, (uint32_t *)vngetpath_bl);
    return *(uint64_t *)(kdata + vngetpath_func);
}

uint64_t find_phys_addr(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 8A FE 52 D3
    //LSR             X10, X20, #0x12
    //AND             X9, X8, #0xFFFFFFFFF000
    //ADRP            X8, #qword_FFFFFF800254E040@PAGE
    
    uint8_t search[] = { 0x8A, 0xFE, 0x52, 0xD3 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    // Find LDR
    uint32_t* ldr_addr = find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_ldr_imm_64);
    if (!ldr_addr)
        return 0;
    
    //PFLog("ldr_addr %p\n", (void *)((uint8_t *)ldr_addr - kdata));
    
    uint64_t pc_ref = find_pc_rel_value_64(region, kdata, ksize, ldr_addr, insn_ldr_imm_rn_64(ldr_addr));
    if (!pc_ref)
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr_addr + 1, insn_ldr_imm_rn_64(ldr_addr));
}

uint64_t find_get_root(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 3F 97 01 31
    //CMN             W25, #0x65
    uint8_t search[] = { 0x3F, 0x97, 0x01, 0x31 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find next cbnz
    uint8_t *cbnz = (uint8_t *)find_next_insn_matching_64(region, kdata, ksize, insn, insn_is_cbnz_w32);
    return (uint64_t)(cbnz - kdata);
}

uint64_t find_sbops(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char sbops[] = "Seatbelt sandbox policy";
    
    uint8_t *sbops_offset = memmem(kdata, ksize, sbops, sizeof(sbops) / sizeof(*sbops));
    if (!sbops_offset)
        return 0;
    uint64_t strAddress = (uintptr_t)sbops_offset - (uintptr_t)kdata + region;
    uint64_t* ref = memmem(kdata, ksize, &strAddress, sizeof(strAddress));
    if (!ref)
        return 0;
    
    uint64_t sandbox_mac_policy_ops_ptr = *(ref + 3);
    return sandbox_mac_policy_ops_ptr - region;
}

uint64_t find_rootvnode(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search 00 11 9F 9A
    //CSEL            X0, X8, XZR, NE
    //First occurence is _vfs_rootvnode
    uint8_t search[] = { 0x00, 0x11, 0x9F, 0x9A };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    //find previous ldr ret
    uint32_t* ldr = find_prev_insn_matching_64(kdata, insn, insn_is_ldr_imm_64);
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr, insn_ldr_imm_rn_64(ldr));
}

uint64_t find_kernproc(uint64_t region, uint8_t* kdata, size_t ksize)
{
    // search C8 10 82 52
    //__TEXT:__text:FFFFFF80024BBC58                 LDR             X8, [X22,#_kernproc@PAGEOFF]
    //__TEXT:__text:FFFFFF80024BBC5C                 STR             X8, [SP,#0x60+var_28]
    //__TEXT:__text:FFFFFF80024BBC60                 MOV             W8, #0xFFFF
    //__TEXT:__text:FFFFFF80024BBC64                 STR             W8, [SP,#0x60+var_44]
    //__TEXT:__text:FFFFFF80024BBC68                 MOV             W8, #0x1086
    uint8_t search[] = { 0xC8, 0x10, 0x82, 0x52 };
    uint32_t* insn = memmem(kdata, ksize, search, sizeof(search) / sizeof(*search));
    if (!insn)
        return 0;
    
    // Find LDR
    uint32_t* ldr_addr = find_prev_insn_matching_64(kdata, insn, insn_is_ldr_imm_64);
    if (!ldr_addr)
        return 0;
    
    //PFLog("ldr_addr %p\n", (void *)((uint8_t *)ldr_addr - kdata));
    
    uint64_t pc_ref = find_pc_rel_value_64(region, kdata, ksize, ldr_addr, insn_ldr_imm_rn_64(ldr_addr));
    if (!pc_ref)
        return 0;
    
    return find_pc_rel_value_64(region, kdata, ksize, ldr_addr + 1, insn_ldr_imm_rn_64(ldr_addr));
}

uint64_t find_cred_label_update_execve(uint64_t region, uint8_t* kdata, size_t ksize)
{
    const char errString[] = "AMFI: hook..execve() killing pid %u: %s";
    uint8_t* errStringPtr = memmem(kdata, ksize, errString, sizeof(errString) - 1);
    if (!errStringPtr)
        return 0;
    //PFLog("%s: errStringPtr %p\n", __PRETTY_FUNCTION__, (void *)(errStringPtr - kdata + region));
    
    // now we have to find code in the kernel referencing to this error string
    uint32_t *adr_instr = find_literal_ref_64(region, kdata, ksize, (uint32_t*)kdata, errStringPtr - kdata);
    if (!adr_instr)
        return 0;
    //PFLog("%s: adr_instr %p\n", __PRETTY_FUNCTION__, (void *)((uint8_t*)adr_instr - kdata + region));
    
    // find previous cbz
    uint32_t *first_cbz = find_last_insn_matching_64(region, kdata, ksize, adr_instr, insn_is_cbz_w32);
    if (!first_cbz)
        return 0;
    
    // find another one
    uint32_t *gta_cbz = find_last_insn_matching_64(region, kdata, ksize, first_cbz, insn_is_cbz_w32);
    if (!gta_cbz)
        return 0;
    
    return (uintptr_t)gta_cbz - (uintptr_t)kdata;
}


// xerub's patchfinder

//extern uint64_t kerndumpbase;
//extern uint64_t xnucore_base;
//extern uint64_t prelink_base;

uint64_t search_handler(uint64_t reg, uint32_t opcode)
{
    uint32_t a=0;
    if((opcode & 0xf9000000) == 0xf9000000){
        uint64_t p = opcode & 0xFFFFFF;
        uint64_t q = p >> 7;
        a = q & 0x7FF8;
    } else if((opcode & 0xf8000000) == 0xf8000000){
        uint64_t p = opcode & 0xFFFFFF;
        uint64_t q = p >> 12;
        a = q & 0xFF;
    } else {
        return 0;
    }
    return reg+a;
}

#endif
