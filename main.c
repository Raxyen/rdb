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
#define GREEN  "\033[32m"
#define YELLOW  "\033[93m"
#define BLUE    "\033[34m"
#define MAGENTA  "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define GRAY    "\033[90m"
#define PURPLE  "\033[38;5;135m"
#define GOLD    "\033[38;5;100m"
#define LIME    "\033[92m"

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

struct instruction_entry {
    char disasm_buf[256];
    char mnemonic_buf[32];
    char operands_buf[128];
};

struct HistoryEntry {
    uint64_t rip;
    struct instruction_entry instruction;
    uint8_t bytes[16];
    size_t instr_len;
};

// globals
struct user_regs_struct regs, prev_regs;
struct stack_val stack_arr[8];

struct HistoryEntry history[HISTORY_SIZE];
struct instruction_entry disasm;

// functions

void addHistory(uint64_t rip, const struct instruction_entry *instruction, uint8_t *bytes, size_t instr_len) {
    for (int i = 0; i < HISTORY_SIZE - 1; i++)
        history[i] = history[i + 1];

    history[HISTORY_SIZE - 1].rip = rip;
    history[HISTORY_SIZE - 1].instruction = *instruction;

    memcpy(history[HISTORY_SIZE - 1].bytes, bytes, 16);
    history[HISTORY_SIZE - 1].instr_len = instr_len;
}

void printRegs(struct user_regs_struct *regs, struct user_regs_struct *prev) {
    printf(CYAN" ──────"YELLOW" Registers "CYAN"───────────────────────────────────────────────────────────────────────\n"WHITE);
    if (prev->rax != regs->rax)
         printf(LIME);
    printf("  rax 0x%016llx"WHITE, regs->rax);
    if (prev->rbx != regs->rbx)
         printf(LIME);
    printf("  rbx 0x%016llx"WHITE, regs->rbx);
    if (prev->rcx != regs->rcx)
         printf(LIME);
    printf("  rcx 0x%016llx\n"WHITE, regs->rcx);

    if (prev->rdx != regs->rdx)
         printf(LIME);
    printf("  rdx 0x%016llx"WHITE, regs->rdx);
    if (prev->rsi != regs->rsi)
         printf(LIME);
    printf("  rsi 0x%016llx"WHITE, regs->rsi);
    if (prev->rdi != regs->rdi)
         printf(LIME);
    printf("  rdi 0x%016llx\n"WHITE, regs->rdi);

    if (prev->rbp != regs->rbp)
         printf(LIME);
    printf("  rbp 0x%016llx"WHITE, regs->rbp);
    if (prev->rsp != regs->rsp)
         printf(LIME);
    printf("  rsp 0x%016llx"WHITE, regs->rsp);
    if (prev->r8 != regs->r8)
         printf(LIME);
    printf("   r8 0x%016llx\n"WHITE, regs->r8);

    if (prev->r9 != regs->r9)
         printf(LIME);
    printf("   r9 0x%016llx"WHITE, regs->r9);
    if (prev->r10 != regs->r10)
         printf(LIME);
    printf("  r10 0x%016llx"WHITE, regs->r10);
    if (prev->r11 != regs->r11)
         printf(LIME);
    printf("  r11 0x%016llx\n"WHITE, regs->r11);

    if (prev->r12 != regs->r12)
         printf(LIME);
    printf("  r12 0x%016llx"WHITE, regs->r12);
    if (prev->r13 != regs->r13)
         printf(LIME);
    printf("  r13 0x%016llx"WHITE, regs->r13);
    if (prev->r14 != regs->r14)
         printf(LIME);
    printf("  r14 0x%016llx\n"WHITE, regs->r14);

    if (prev->r15 != regs->r15)
         printf(LIME);
    printf("  r15 0x%016llx\n"WHITE, regs->r15);


}

void printStack(struct stack_val *stack, struct user_regs_struct *regs, size_t size) {
    printf(CYAN" ──────"YELLOW" Stack "CYAN"───────────────────────────────────────────────────────────────────────────\n"WHITE);
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

void formatMemory(char *buf, size_t size, const char *base, int32_t disp) {
    if (disp == 0)
        snprintf(buf, size, "QWORD PTR [%s]", base);
    else if (disp > 0)
        snprintf(buf, size, "QWORD PTR [%s+%d]", base, disp);
    else
        snprintf(buf, size, "QWORD PTR [%s%d]", base, disp);
}

struct instruction_entry *disassemble(unsigned char *bytes) {
    struct instruction *current;
    size_t pos = 0;
    size_t start_pos = pos;

    memset(&disasm, 0, sizeof(disasm));

    struct instruction no_args_opcodes[] = { 
        {0x90, "nop", 1},
        {0xC3, "ret", 1},
        {0xCC, "int3", 1},

        // stack operations
        {0x50, "push rax", 1},
        {0x51, "push rcx", 1},
        {0x52, "push rdx", 1},
        {0x53, "push rcx", 1},
        {0x54, "push rsp", 1},
        {0x55, "push rbp", 1},
        {0x56, "push rsi", 1},
        {0x57, "push rdi", 1},
        {0x58, "pop rax", 1},
        {0x5F, "pop rdi", 1}, 
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
        // move
        {0x88, "mov",  -1, RM_REG, 0},        // mov r/m8, r8
        {0x89, "mov",  -1, RM_REG, 0},        // mov r/m32/64, r32/64
        {0x8B, "mov",  -1, REG_RM, 0},        // mov r32/64, r/m32/64
        {0xC7, "mov",  -1, RM_IMM, 4},        // mov r/m32/64, imm32

        {0x8D, "lea",  -1, REG_RM, 0},        // lea r32/64, m

        // arithmetic
        {0x00, "add",  -1, RM_REG, 0},        // add r/m8, r8
        {0x01, "add",  -1, RM_REG, 0},        // add r/m32/64, r32/64
        {0x02, "add",  -1, REG_RM, 0},        // add r8, r/m8
        {0x03, "add",  -1, REG_RM, 0},        // add r32/64, r/m32/64
        {0x04, "add",  -1, FIXEDREG_IMM, 1},  // add al, imm8
        {0x05, "add",  -1, FIXEDREG_IMM, 4},  // add eax/rax, imm32

        {0x29, "sub",  -1, RM_REG, 0},        // sub r/m32/64, r32/64
        {0x2B, "sub",  -1, REG_RM, 0},        // sub r32/64, r/m32/64

        // bitwise
        {0x21, "and",  -1, RM_REG, 0},
        {0x23, "and",  -1, REG_RM, 0},

        {0x09, "or",   -1, RM_REG, 0},
        {0x0B, "or",   -1, REG_RM, 0},

        {0x31, "xor",  -1, RM_REG, 0},
        {0x33, "xor",  -1, REG_RM, 0},

        // compare
        {0x85, "test", -1, RM_REG, 0},        // test r/m32/64, r32/64
        {0x39, "cmp",  -1, RM_REG, 0},
        {0x3B, "cmp",  -1, REG_RM, 0},         
        
        // already not resolved opcode groups 
        {0x80, "grp80",-1, RM_IMM, 1},        // grp r/m8, imm8
        {0x81, "grp81",-1, RM_IMM, 4},        // grp r/m32/64, imm32
        {0x83, "grp83",-1, RM_IMM, 1},        // grp r/m32/64, imm8 sign-extended
    };

    const char *regs64[16] = { 
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };

    // push without REX byte
    if (bytes[pos] >= 0x50 && bytes[pos] <= 0x57) {
        const char *reg = regs64[bytes[pos++] - 0x50];
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", "push");
        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s", reg);
        snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
        return &disasm;
    }

    else if (isRex(bytes[pos])) { // executed if first byte of an instruction is REX

        struct rex_prefix rex = parseRex(bytes[pos++]); // pos = 0, will be = 1
        
        // push with REX byte
        if (bytes[pos] >= 0x50 && bytes[pos] <= 0x57) {
            const char *reg = regs64[bytes[pos] - 0x48];
            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", "push");
            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s", reg);
            snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
            return &disasm;
        }

        current = search(rex_opcodes, (sizeof(rex_opcodes) / sizeof(rex_opcodes[0])), (uint16_t)bytes[pos++]); // pos = 1, will be = 2

        if (current != NULL) {
            // if instruction is not in the group
            if (strcmp(current->mnemonic, "grp80") && strcmp(current->mnemonic, "grp81") && strcmp(current->mnemonic, "grp83"))
                snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);

            uint8_t modrm = bytes[pos++];
       
            uint8_t mod = ((modrm >> 0x6) & 0x3);
            uint8_t reg = (modrm >> 0x3) & 0x7;
            uint8_t rm = modrm & 0x7;        
            
            uint8_t dst;
            uint8_t src;

            if (!strcmp(current->mnemonic, "grp80") || !strcmp(current->mnemonic, "grp81") || !strcmp(current->mnemonic, "grp83")) {
                char *mnemonic;
                switch (reg) {
                    case 0x0:
                        mnemonic = "add";
                        break;
                    case 0x5:
                        mnemonic = "sub";
                        break;
                    case 0x7:
                        mnemonic = "cmp";
                        break;
                }
                snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", mnemonic);
            }

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
                                disp = *(int32_t *)&bytes[pos];
                                pos += 4;
                            }

                            if (index == 0x4 && !rex.x) { // no index
                                if (base == 0x5) // no index, no base                                  
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR ["PURPLE"0x%08x"WHITE"]", "%s", disp, regs64[src]); 
                                else // no index, base exists                                    
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s], %s", regs64[base + (rex.b << 0x3)], regs64[src]);                                 
                            }
                            else { // index exists
                                if (base == 0x5) // index exists, no base                      
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s * %d + "PURPLE"0x%08x"WHITE"], %s", regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                                else // index exists, base exists
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, regs64[src]); 
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [RIP+"PURPLE"0x%08x"WHITE"], %s", disp, regs64[src]);    
                        }                    
                        else {
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s], %s", regs64[dst], regs64[src]);  
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

                            int32_t disp = 0;

                            if (base == 0x5) {
                                disp = *(int32_t *)&bytes[pos];
                                pos += 4;
                            }

                            if (index == 0x4 && !rex.x) { // no index
                                if (base == 0x5) // no index, no base
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR ["PURPLE"0x%08x"WHITE"]", regs64[dst], disp);                          
                                else { // no index, base exists                                    
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s]", regs64[dst], regs64[base + (rex.b << 0x3)]); 
                                }
                            }
                            else { // index exists
                                if (base == 0x5) { // index exists, no base                                   
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s * %d + "PURPLE"0x%08x"WHITE"]", regs64[dst], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                                }
                                else { // index exists, base exists
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s + %s * %d]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss); 
                                }
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [RIP+"PURPLE"0x%08x"WHITE"]", regs64[dst], disp); 
                        }
                        else
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s]", regs64[dst], regs64[src]); 
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
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR ["PURPLE"0x%08x"WHITE"], %+d", disp, imm);
                                else
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s], %+d", regs64[base + (rex.b << 3)], imm);
                            }
                            else {
                                if (base == 0x5)
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s * %d + "PURPLE"0x%08x"WHITE"], %+d", regs64[index + (rex.x << 3)], 1 << ss, disp, imm);
                                else {
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d], %+d", regs64[base + (rex.b << 3)], regs64[index + (rex.x << 3)], 1 << ss, imm);
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [RIP+"PURPLE"0x%08x"WHITE"], %+d", disp, imm);
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s], %+d", regs64[dst], imm);
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[base + (rex.b << 0x3)], disp, regs64[src]); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d "PURPLE"%+d"WHITE"], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[5 + (rex.b << 0x3)], disp, regs64[src]);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[dst], disp, regs64[src]); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s + %s * %d "PURPLE"%+d"WHITE"]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[src], disp); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s%"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d "PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[5 + (rex.b << 0x3)], disp, imm);  
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
                            
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[dst], disp, imm); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[base + (rex.b << 0x3)], disp, regs64[src]); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d "PURPLE"%+d"WHITE"], %s", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, regs64[src]); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[5 + (rex.b << 0x3)], disp, regs64[src]);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], %s", regs64[dst], disp, regs64[src]); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR  [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR  [%s + %s * %d "PURPLE"%+d"WHITE"]", regs64[dst], regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR  [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"]", regs64[dst], regs64[src], disp); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR  [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s + %s * %d "PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[base + (rex.b << 0x3)], regs64[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR  [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[5 + (rex.b << 0x3)], disp, imm);  
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
                            
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"QWORD"WHITE" PTR [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE"", regs64[dst], disp, imm); 
                        }
                    }
                break;
                case 0x3: // both operands are registers (or one of them is imm)
                    if (current->order == RM_REG) {
                        dst = rex.b ? rm + 8 : rm;
                        src = rex.r ? reg + 8 : reg;                      
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, %s", regs64[dst], regs64[src]);  
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.r ? reg + 8 : reg;
                        src = rex.b ? rm + 8 : rm;
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, %s", regs64[dst], regs64[src]);  
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 8 : rm;
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "PURPLE"0x%02x"WHITE, regs64[dst], bytes[pos++]);  
                    }             
                break;
            }   
        }
        else {
            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), RED"UNKNOWN"WHITE);
            last_instr_len = pos - start_pos;
            return &disasm;
        }
    }
    else if ((current = search(jumps_opcodes, (sizeof(jumps_opcodes) / sizeof(jumps_opcodes[0])), (uint16_t)(bytes[pos++]))) != NULL) { // jump instructions and other with only one operand
        int8_t rel = (int8_t)bytes[pos++];
        uint64_t target = regs.rip + current->length + rel;
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);
        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), PURPLE"0x%llx"WHITE, target);
    }
    else if ((current = search(no_args_opcodes, (sizeof(no_args_opcodes) / sizeof(no_args_opcodes[0])), (uint16_t)(bytes[pos++]))) != NULL) {
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);
    }
    else {
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), RED"UNKNOWN"WHITE);
    }

    if (sizeof(disasm.operands_buf) != 0)
        snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
    else
        snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE, disasm.mnemonic_buf);

    last_instr_len = pos - start_pos;
    return &disasm;
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

                for (size_t j = 0; j < 8; j++) { // get 16 bytes starting from a byter RIP is pointing to
                    stack_arr[j].val = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp + j * 8), NULL);
                    stack_arr[j].addr = regs.rsp + j * 8;
                }

                printStack(stack_arr, &regs, 8);

                printf(CYAN" ──────"YELLOW" Assembly "CYAN"────────────────────────────────────────────────────────────────────────\n"WHITE);
                long value1 = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);
                long value2 = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip + 8, NULL);
                
                uint8_t bytes[16];
                memcpy(bytes, &value1, 8);
                memcpy(bytes + 8, &value2, 8);        
                                     
                struct instruction_entry *instr = disassemble(bytes);
                addHistory(regs.rip, instr, bytes, last_instr_len);

                printf(CYAN"  %-19s %-24s %s\n"WHITE, "ADDRESS", "BYTES", "INSTRUCTION");

                for (int j = 0; j < HISTORY_SIZE; j++) {

                    if (history[j].instruction.mnemonic_buf[0] == '\0')
                        continue;

                    char bytes_buf[64] = {0};

                    for (int k = 0; k < history[j].instr_len; k++) {
                        char tmp[8];
                        snprintf(tmp, sizeof(tmp), "%02x ", history[j].bytes[k]);
                        strncat(bytes_buf, tmp, sizeof(bytes_buf) - strlen(bytes_buf) - 1);
                    }

                    printf(GRAY"  0x%016llx  "WHITE"%-24s %s\n", history[j].rip, bytes_buf, history[j].instruction.disasm_buf);                   
                }

                printf(CYAN" ────────────────────────────────────────────────────────────────────────────────────────\n"WHITE);

                prev_regs = regs;

                usleep(100000);
            }
        }
    }
    return 0;
}
