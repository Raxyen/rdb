#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>

#define HISTORY_SIZE 8

// tty colors

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define PURPLE  "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

// enums

enum operand_order {
    REG_RM,
    RM_REG,
    RM_IMM,
    FIXEDREG_IMM
};

// structures

struct stack_val {
    long val;
    long addr;
};

struct instruction {
    uint16_t opcode;
    const char *mnemonic;
    int length;
    enum operand_order order;
    uint8_t imm_size;
};

struct rex_prefix {
    int w;
    int r;
    int x;
    int b;
};

struct HistoryEntry {
    uint64_t rip;
    char instruction[128];
    uint8_t bytes[16];
    size_t instr_len;
};

// globals
struct user_regs_struct regs, prev_regs;
struct stack_val stack_arr[8];

struct HistoryEntry history[HISTORY_SIZE];

char disasm_buf[256];
char operands_buf[128];

// functions

void addHistory(uint64_t rip, const char *instruction, uint8_t *bytes, size_t instr_len)
{
    for (int i = 0; i < HISTORY_SIZE - 1; i++)
        history[i] = history[i + 1];

    history[HISTORY_SIZE - 1].rip = rip;

    strncpy(
        history[HISTORY_SIZE - 1].instruction,
        instruction,
        sizeof(history[0].instruction) - 1
    );

    memcpy(
        history[HISTORY_SIZE - 1].bytes,
        bytes,
        16
    );

    history[HISTORY_SIZE - 1].instr_len = instr_len;
}

void printRegs(struct user_regs_struct *regs, struct user_regs_struct *prev) {
    printf(CYAN" ══════"YELLOW" REGISTERS "CYAN"═══════════════════════════════════════\n"WHITE);
    if (prev->rip != regs->rip)
        printf(GREEN);
    printf("  RIP: 0x%016llx"WHITE, regs->rip);
    if (prev->rdi != regs->rdi)
        printf(GREEN);
    printf("  RDI: 0x%016llx \n"WHITE, regs->rdi);
    if (prev->rsp != regs->rsp)
        printf(GREEN);
    printf("  RSP: 0x%016llx"WHITE, regs->rsp);
    if (prev->rsi != regs->rsi)
        printf(GREEN);
    printf("  RSI: 0x%016llx \n"WHITE, regs->rsi);
    if (prev->rbp != regs->rbp)
        printf(GREEN);
    printf("  RBP: 0x%016llx \n", regs->rbp);
    printf(CYAN" ════════════════════════════════════════════════════════\n"WHITE);
    if (prev->rax != regs->rax)
        printf(GREEN);
    printf("  RAX: 0x%016llx"WHITE, regs->rax);
    if (prev->r8 != regs->r8)
        printf(GREEN);
    printf("   R8: 0x%016llx\n"WHITE, regs->r8);
    if (prev->rbx != regs->rbx)
        printf(GREEN);
    printf("  RBX: 0x%016llx"WHITE, regs->rbx);
    if (prev->r9 != regs->r9)
        printf(GREEN);
    printf("   R9: 0x%016llx\n"WHITE, regs->r9);
    if (prev->rcx != regs->rcx)
        printf(GREEN);
    printf("  RCX: 0x%016llx"WHITE, regs->rcx);
    if (prev->r10 != regs->r10)
        printf(GREEN);
    printf("  R10: 0x%016llx\n"WHITE, regs->r10);
    if (prev->rdx != regs->rdx)
        printf(GREEN);
    printf("  RDX: 0x%016llx"WHITE, regs->rdx);
    if (prev->r11 != regs->r11)
        printf(GREEN);
    printf("  R11: 0x%016llx\n"WHITE, regs->r11);
    if (prev->r12 != regs->r12)
        printf(GREEN);
    printf("  R12: 0x%016llx"WHITE, regs->r12);
    if (prev->r13 != regs->r13)
        printf(GREEN);
    printf("  R13: 0x%016llx\n"WHITE, regs->r13);
    if (prev->r14 != regs->r14)
        printf(GREEN);
    printf("  R14: 0x%016llx"WHITE, regs->r14);
    if (prev->r15 != regs->r15)
        printf(GREEN);
    printf("  R15: 0x%016llx\n"WHITE, regs->r15);
}

void printStack(struct stack_val *stack, struct user_regs_struct *regs, size_t size) {
    printf(CYAN" ══════"YELLOW" STACK "CYAN"══════════════════════════════════════════\n"WHITE);
    for (size_t i = 0; i < size; i++) {
        printf("  0x%016lx [rsp+%2zu]: 0x%016lx ", stack[i].addr, i * 8, stack[i].val);
        if (stack[i].addr == regs->rsp)
            printf(BLUE" <- RSP"WHITE);
        if (stack[i].addr == regs->rbp)
            printf(BLUE" <- RBP"WHITE);
        printf("\n");
    }
}

// disassembly

struct instruction *search(struct instruction *set, size_t count, uint16_t opcode) {
    for (size_t i = 0; i < count; i++) {
        if (set[i].opcode == opcode)
            return &set[i];
    }
    return NULL;
}

int isRex(unsigned char byte) {
    return (byte & 0xF0) == 0x40;
}

struct rex_prefix parseRex(unsigned char byte) {
    struct rex_prefix rex;
    rex.w = (byte >> 3) & 1;
    rex.r = (byte >> 2) & 1;
    rex.x = (byte >> 1) & 1;
    rex.b = byte & 1;
    return rex;
}

size_t last_instr_len;

char *disassemble(unsigned char *bytes) {
    struct instruction *current;
    size_t pos = 0;
    size_t start_pos = pos;

    memset(disasm_buf, 0, 256);

    // used if bytes[0] != 0x48 
    struct instruction no_args_opcodes[] = { 
        {0x90, "nop", 1},
        {0xC3, "ret", 1},
        {0xCC, "int3", 1},

        {0x55, "push rbp", 1},
        {0x5D, "pop rbp", 1},      
    };

    struct instruction jumps_opcodes[] = {
        {0x74, "je", 2}, // je rel8
        {0x75, "jne", 2}, // jne rel8
        {0x76, "jbe", 2}, // jbe rel8
        {0x77, "ja", 2}, // ja rel8

        {0xEB, "jmp", 2}, // jmp rel8

        {0xE8, "call", 5}, // call rel32
        {0xE9, "jmp", 5} // jmp rel32
    };

    struct instruction rex_opcodes[] = {
        {0x88, "mov",  -1, RM_REG, 0},        // mov r/m8, r8
        {0x89, "mov",  -1, RM_REG, 0},        // mov r/m32/64, r32/64
        {0x8B, "mov",  -1, REG_RM, 0},        // mov r32/64, r/m32/64
        {0xC7, "mov",  -1, RM_IMM, 4},        // mov r/m32/64, imm32

        {0x00, "add",  -1, RM_REG, 0},        // add r/m8, r8
        {0x01, "add",  -1, RM_REG, 0},        // add r/m32/64, r32/64
        {0x02, "add",  -1, REG_RM, 0},        // add r8, r/m8
        {0x03, "add",  -1, REG_RM, 0},        // add r32/64, r/m32/64
        {0x04, "add",  -1, FIXEDREG_IMM, 1},  // add al, imm8
        {0x05, "add",  -1, FIXEDREG_IMM, 4},  // add eax/rax, imm32

        {0x8D, "lea",  -1, REG_RM, 0},        // lea r32/64, m

        {0x85, "test", -1, RM_REG, 0},        // test r/m32/64, r32/64

        {0x80, "grp80",-1, RM_IMM, 1},        // grp r/m8, imm8
        {0x81, "grp81",-1, RM_IMM, 4},        // grp r/m32/64, imm32
        {0x83, "grp83",-1, RM_IMM, 1},        // grp r/m32/64, imm8 sign-extended
    };

    if (isRex(bytes[pos])) { // executed if first byte of an instruction is REX
        const char *regs64[16] = { 
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        };
        
        struct rex_prefix rex = parseRex(bytes[pos++]); // pos = 0, will be = 1
        current = search(rex_opcodes, (sizeof(rex_opcodes) / sizeof(rex_opcodes[0])), (uint16_t)bytes[pos++]); // pos = 1, will be = 2

        if (current != NULL) {
            snprintf(disasm_buf, sizeof(disasm_buf), "%s", current->mnemonic);
            uint8_t modrm = bytes[pos++];
       
            uint8_t mod = ((modrm >> 0x6) & 0x3);
            uint8_t reg = (modrm >> 0x3) & 0x7;
            uint8_t rm = modrm & 0x7;        
            
            uint8_t dst;
            uint8_t src;

            switch (mod) {           
                case 0x0: // memory addressing           
                    if (current->order == RM_REG) {                   
                        dst = rex.b ? rm + 0x8 : rm;
                        src = rex.r ? reg + 0x8 : reg;                                          

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;

                            int32_t disp = 0;

                            if (base == 0x5) {
                                int32_t disp = *(int32_t *)&bytes[pos];
                                pos += 4;
                            }

                            if (index == 0x4 && !rex.x) { // no index
                                if (base == 0x5) // no index, no base                                  
                                    snprintf(operands_buf, sizeof(operands_buf), "    [0x%08x], %s", disp, regs64[src]); 
                                else // no index, base exists                                    
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s], %s", regs64[base + (rex.b << 0x3)], regs64[src]);                                 
                            }
                            else { // index exists
                                if (base == 0x5) // index exists, no base                      
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s * %d + 0x%08x], %s", regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                                else // index exists, base exists
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, regs64[src]); 
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    [RIP+0x%08x], %s", disp, regs64[src]);    
                        }                    
                        else {
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s], %s", regs64[dst], regs64[src]);  
                        }
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.b ? rm + 0x8 : rm;
                        src = rex.r ? reg + 0x8 : reg;                                          

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;

                            int32_t disp = 0;

                            if (base == 0x5) {
                                disp = *(int32_t *)&bytes[pos];
                                pos += 4;
                            }

                            if (index == 0x4 && !rex.x) { // no index
                                if (base == 0x5) // no index, no base
                                    snprintf(operands_buf, sizeof(operands_buf), "    %s, [0x%08x]", regs64[dst], disp);                          
                                else { // no index, base exists                                    
                                    snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s]", regs64[dst], regs64[base + (rex.b << 0x3)]); 
                                }
                            }
                            else { // index exists
                                if (base == 0x5) { // index exists, no base                                   
                                    snprintf(operands_buf, sizeof(operands_buf),"    %s, [%s * %d + 0x%08x]", regs64[dst], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                                }
                                else { // index exists, base exists
                                    snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s + %s * %d]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss); 
                                }
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [RIP+0x%08x]", regs64[dst], disp); 
                        }
                        else
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s]", regs64[dst], regs64[src]); 
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 0x8 : rm;

                        int32_t imm;

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 6) & 0x3;
                            uint8_t index = (sib >> 3) & 0x7;
                            uint8_t base = sib & 0x7;

                            int32_t disp = 0;

                            if (base == 0x5) {
                                disp = *(int32_t *)&bytes[pos];
                                pos += 4;
                            }

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }
                        
                            if (index == 0x4 && !rex.x) {
                                if (base == 0x5)
                                    snprintf(operands_buf, sizeof(operands_buf), "    [0x%08x], %+d", disp, imm);                              
                                else
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s], %+d", regs64[base + (rex.b << 3)], imm);
                            }
                            else {
                                if (base == 0x5)
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s * %d + 0x%08x], %+d", regs64[index + (rex.x << 3)], 1 << ss, disp, imm);
                                else {
                                    snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d], %+d", regs64[base + (rex.b << 3)], regs64[index + (rex.x << 3)], 1 << ss, imm);
                                }
                            }
                        }
                        else if (rm == 0x5) {

                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            snprintf(operands_buf, sizeof(operands_buf), "    [RIP+0x%08x], %+d", disp, imm);
                        }
                        else {

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            snprintf(operands_buf, sizeof(operands_buf), "    [%s], %+d", regs64[dst], imm);
                        }
                    }
                break;
                case 0x1:
                    if (current->order == RM_REG) {                   
                        dst = rex.b ? rm + 0x8 : rm;
                        src = rex.r ? reg + 0x8 : reg;                                          
                       
                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int8_t disp = (int8_t)bytes[pos++];
                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[base + (rex.b << 0x3)], disp, regs64[src]); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d %+d], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[5 + (rex.b << 0x3)], disp, regs64[src]);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[dst], disp, regs64[src]); 
                        }
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.r ? reg + 0x8 : reg;
                        src = rex.b ? rm + 0x8 : rm;

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int8_t disp = (int8_t)bytes[pos++];
                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s + %s * %d %+d]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[src], disp); 
                        }  
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 0x8 : rm;

                        int32_t imm;

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int8_t disp = (int8_t)bytes[pos++];

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %+d", regs64[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d %+d], %+d", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            snprintf(operands_buf, sizeof(operands_buf),"    [%s%+d], %+d", regs64[5 + (rex.b << 0x3)], disp, imm);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }
                            
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %+d", regs64[dst], disp, imm); 
                        }
                    }
                break;
                case 0x2:
                    if (current->order == RM_REG) {                   
                        dst = rex.b ? rm + 0x8 : rm;
                        src = rex.r ? reg + 0x8 : reg;                                          
                       
                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[base + (rex.b << 0x3)], disp, regs64[src]); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d %+d], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[5 + (rex.b << 0x3)], disp, regs64[src]);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %s", regs64[dst], disp, regs64[src]); 
                        }
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.r ? reg + 0x8 : reg;
                        src = rex.b ? rm + 0x8 : rm;

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s + %s * %d %+d]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(operands_buf, sizeof(operands_buf), "    %s, [%s%+d]", regs64[dst], regs64[src], disp); 
                        }  
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 0x8 : rm;

                        int32_t imm;

                        if (rm == 0x4) {
                            uint8_t sib = bytes[pos++];
                            uint8_t ss = (sib >> 0x6) & 0x3;
                            uint8_t index = (sib >> 0x3) & 0x7;
                            uint8_t base = sib & 0x7;
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            if (index == 0x4 && !rex.x)
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %+d", regs64[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(operands_buf, sizeof(operands_buf), "    [%s + %s * %d %+d], %+d", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }

                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %+d", regs64[5 + (rex.b << 0x3)], disp, imm);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;

                            switch(current->imm_size) {
                                case 1:
                                    imm = (int8_t)bytes[pos];
                                    pos += 1;
                                break;

                                case 4:
                                    imm = *(int32_t *)&bytes[pos];
                                    pos += 4;
                                break;
                            }
                            
                            snprintf(operands_buf, sizeof(operands_buf), "    [%s%+d], %+d", regs64[dst], disp, imm); 
                        }
                    }
                break;
                case 0x3: // both operands are registers (or one of them is imm)
                    if (current->order == RM_REG) {
                        dst = rex.b ? rm + 8 : rm;
                        src = rex.r ? reg + 8 : reg;                      
                        snprintf(operands_buf, sizeof(operands_buf), "    %s, %s", regs64[dst], regs64[src]);  
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.r ? reg + 8 : reg;
                        src = rex.b ? rm + 8 : rm;
                        snprintf(operands_buf, sizeof(operands_buf), "    %s, %s", regs64[dst], regs64[src]);  
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 8 : rm;
                        snprintf(operands_buf, sizeof(operands_buf), "    %s, 0x%02x", regs64[dst], bytes[3]);  
                    }             
                break;
            }   
        }
        else {
            snprintf(disasm_buf, sizeof(disasm_buf), RED"UNKNOWN"WHITE);
            last_instr_len = pos - start_pos;
            return disasm_buf;
        }
    }
    else if ((current = search(jumps_opcodes, (sizeof(jumps_opcodes) / sizeof(jumps_opcodes[0])), (uint16_t)(bytes[pos++]))) != NULL) { // jump instructions and other with only one operand
        int8_t rel = (int8_t)bytes[pos];
        uint64_t target = regs.rip + current->length + rel;
        snprintf(disasm_buf, sizeof(disasm_buf), "%s 0x%llx", current->mnemonic, target);
    }
    else if ((current = search(no_args_opcodes, (sizeof(no_args_opcodes) / sizeof(no_args_opcodes[0])), (uint16_t)(bytes[pos]))) != NULL) {
        snprintf(disasm_buf, sizeof(disasm_buf), "%s", current->mnemonic);
    }
    else {
        snprintf(disasm_buf, sizeof(disasm_buf), RED"UNKNOWN"WHITE);
    }

    strncat(disasm_buf, operands_buf, sizeof(disasm_buf) - strlen(disasm_buf) - 1);
    last_instr_len = pos - start_pos;
    return disasm_buf;
}

// main function
int main(int argc, char *argv[]) {

    if (argc != 3) {
        fprintf(stderr, "Usage: ./proto <exectuable> <number of instructions>");
        return 1;
    }

    pid_t pid;
    int status;

    if ((pid = fork()) == -1) {
        perror("fork");
        return 1;
    }
    else if (pid == 0) {
        // child process, program to trace and debug
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (execvp(argv[1], &argv[1]) == -1) {
            perror("execvp");
            _exit(1);
        }
    }
    else {
        waitpid(pid, &status, 0);
        WSTOPSIG(status);
        if (WIFSTOPPED(status)) {
            size_t number_of_instructions = (size_t)atoi(argv[2]);

            for (size_t i = 0; i < number_of_instructions; i++) {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                waitpid(pid, &status, 0);
                WSTOPSIG(status);                                          

                ptrace(PTRACE_GETREGS, pid, NULL, &regs); // get registers   
                 
                if (i == 0) {
                    prev_regs = regs;
                }

                printf("\033[2J");
                printf("\033[H");

                printRegs(&regs, &prev_regs);           

                for (size_t j = 0; j < 8; j++) {
                    stack_arr[j].val = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp + j * 8), NULL);
                    stack_arr[j].addr = regs.rsp + j * 8;
                }

                printStack(stack_arr, &regs, 8);

                printf(CYAN" ══════"YELLOW" DISASSEMBLY "CYAN"══════════════════════════════════════════\n"WHITE);
                long value1 = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);
                long value2 = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip + 8, NULL);
                
                uint8_t bytes[16];
                memcpy(bytes, &value1, 8);
                memcpy(bytes + 8, &value2, 8);        
                                     
                char *instr = disassemble(bytes);
                addHistory(regs.rip, instr, bytes, last_instr_len);

                printf(CYAN"  %-19s %-24s %s\n"WHITE, "ADDRESS", "BYTES", "INSTRUCTION");

                for (int j = 0; j < HISTORY_SIZE; j++) {

                    if (history[j].instruction[0] == '\0')
                        continue;

                    char bytes_buf[64] = {0};

                    for (int k = 0; k < history[j].instr_len; k++) {
                        char tmp[8];
                        snprintf(tmp, sizeof(tmp), "%02x ", history[j].bytes[k]);
                        strncat(bytes_buf, tmp, sizeof(bytes_buf) - strlen(bytes_buf) - 1);
                    }

                    printf("  0x%016llx  %-24s %s\n", history[j].rip, bytes_buf, history[j].instruction);
                }

                prev_regs = regs;
                
                usleep(100000);
            }
        }
    }
    return 0;
}
