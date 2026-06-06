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

#define HISTORY_SIZE 16

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
    char *operand_size;
    char *fixed_reg;
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

struct instruction_entry *disassemble(unsigned char *bytes) {
    struct instruction *current;
    size_t pos = 0;
    size_t start_pos = pos;

    disasm.mnemonic_buf[0] = '\0';
    disasm.operands_buf[0] = '\0';
    disasm.disasm_buf[0] = '\0';

    struct instruction no_args_opcodes[] = { 
        {0x90, "nop", 1},
        {0xC3, "ret", 1},
        {0xCC, "int3", 1},
    };

    struct instruction jumps_opcodes[] = {
        {0x70, "jo",   2}, // overflow
        {0x71, "jno",  2}, // not overflow

        {0x72, "jb",   2}, // below (CF=1)
        {0x73, "jae",  2}, // above or equal

        {0x74, "je",   2},
        {0x75, "jne",  2},

        {0x76, "jbe",  2},
        {0x77, "ja",   2},

        {0x78, "js",   2}, // sign
        {0x79, "jns",  2}, // not sign

        {0x7A, "jp",   2}, // parity
        {0x7B, "jnp",  2}, // not parity

        {0x7C, "jl",   2}, // less
        {0x7D, "jge",  2}, // greater or equal

        {0x7E, "jle",  2}, // less or equal
        {0x7F, "jg",   2}, // greater

        {0xEB, "jmp",  2}, // rel8

        {0xE8, "call", 5}, // rel32
        {0xE9, "jmp",  5}  // rel32
    };

    struct instruction rex_opcodes[] = {
        // move
        {0x88, "mov",  -1, RM_REG,       0, "BYTE"},   // mov r/m8, r8
        {0x89, "mov",  -1, RM_REG,       0, "QWORD"},  // mov r/m64, r64
        {0x8B, "mov",  -1, REG_RM,       0, "QWORD"},  // mov r64, r/m64
        {0xC7, "mov",  -1, RM_IMM,       4, "QWORD"},  // mov r/m64, imm32

        {0xB0, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov al, imm8
        {0xB1, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov cl, imm8
        {0xB2, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov dl, imm8
        {0xB3, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov bl, imm8
        {0xB4, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov ah, imm8
        {0xB5, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov ch, imm8
        {0xB6, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov dh, imm8
        {0xB7, "mov",   2, FIXEDREG_IMM, 1, ""},       // mov bh, imm8

        {0xB8, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov eax, imm32
        {0xB9, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov ecx, imm32
        {0xBA, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov edx, imm32
        {0xBB, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov ebx, imm32
        {0xBC, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov esp, imm32
        {0xBD, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov ebp, imm32
        {0xBE, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov esi, imm32
        {0xBF, "mov",   5, FIXEDREG_IMM, 4, ""},       // mov edi, imm32

        {0x8D, "lea",  -1, REG_RM,       0, ""},         // lea r64, m

        // arithmetic
        {0x00, "add",  -1, RM_REG,       0, "BYTE"},   // add r/m8, r8
        {0x01, "add",  -1, RM_REG,       0, "QWORD"},  // add r/m64, r64
        {0x02, "add",  -1, REG_RM,       0, "BYTE"},   // add r8, r/m8
        {0x03, "add",  -1, REG_RM,       0, "QWORD"},  // add r64, r/m64
        {0x04, "add",  -1, FIXEDREG_IMM, 1, ""},         // add al, imm8
        {0x05, "add",  -1, FIXEDREG_IMM, 4, ""},         // add rax, imm32

        {0x11, "adc",  -1, RM_REG,       0, "QWORD"},
        {0x13, "adc",  -1, REG_RM,       0, "QWORD"},

        {0x19, "sbb",  -1, RM_REG,       0, "QWORD"},
        {0x1B, "sbb",  -1, REG_RM,       0, "QWORD"},

        {0x29, "sub",  -1, RM_REG,       0, "QWORD"},  // sub r/m64, r64
        {0x2B, "sub",  -1, REG_RM,       0, "QWORD"},  // sub r64, r/m64

        // bitwise
        {0x21, "and",  -1, RM_REG,       0, "QWORD"},
        {0x23, "and",  -1, REG_RM,       0, "QWORD"},

        {0x09, "or",   -1, RM_REG,       0, "QWORD"},
        {0x0B, "or",   -1, REG_RM,       0, "QWORD"},

        {0x31, "xor",  -1, RM_REG,       0, "QWORD"},
        {0x33, "xor",  -1, REG_RM,       0, "QWORD"},

        {0x85, "test", -1, RM_REG,       0, "QWORD"}, // test r/m32/64, r32/64

        // compare       
        {0x39, "cmp",  -1, RM_REG,       0, "QWORD"},
        {0x3B, "cmp",  -1, REG_RM,       0, "QWORD"},

        // opcode groups
        {0x80, "grp80",-1, RM_IMM,       1, "BYTE" },   // r/m8, imm8
        {0x81, "grp81",-1, RM_IMM,       4, "QWORD"},  // r/m64, imm32
        {0x83, "grp83",-1, RM_IMM,       1, "QWORD"},   // r/m64, imm8
        {0xC1, "grpC1",-1, RM_IMM,       1, "QWORD"},

        // exchange
        {0x87, "xchg", -1, RM_REG, 0, "QWORD"},

        // push/pop memory
        {0x8F, "pop",  -1, RM_REG, 0, "QWORD"},

        // sign extend
        {0x63, "movsxd", -1, REG_RM, 0, "DWORD"}
    };

    const char *regs64[16] = { 
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };

    const char *regs32[16] = { 
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };

    const char *regs8_legacy[8] = {
        "al", "cl", "dl", "bl",
        "ah", "ch", "dh", "bh"
    };

    const char *regs8_rex[16] = {
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
    };

    if ((current = search(jumps_opcodes, (sizeof(jumps_opcodes) / sizeof(jumps_opcodes[0])), (uint16_t)(bytes[pos]))) != NULL) { // jump instructions and other with only one operand
        int64_t rel;
        pos++; // pos = 1;

        if (current->length == 2) {
            rel = (int8_t)bytes[pos];
            pos += 1;
        }
        else if (current->length == 5) {
            rel = *(int32_t *)&bytes[pos];
            pos += 4;
        }
        
        uint64_t target = regs.rip + current->length + rel;
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);
        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), PURPLE"0x%llx"WHITE, target);
        snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
        last_instr_len = pos - start_pos;
        return &disasm;
    }

    else if ((current = search(no_args_opcodes, (sizeof(no_args_opcodes) / sizeof(no_args_opcodes[0])), (uint16_t)(bytes[pos]))) != NULL) {
        snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);
        snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
        last_instr_len = pos - start_pos;
        return &disasm;
    }

    else {
        struct rex_prefix rex = {0};
        int is_rex = isRex(bytes[pos]);
        
        if (is_rex)
            rex = parseRex(bytes[pos++]); // pos = 0, will be = 1
        
        // push reg
        if (bytes[pos] >= 0x50 && bytes[pos] <= 0x57) {
            uint8_t opcode = bytes[pos++];

            uint8_t reg_no = opcode - 0x50;

            if (rex.b)
                reg_no += 8;

            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "push");
            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s", regs64[reg_no]);
            snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD "%-10s" WHITE "%s", disasm.mnemonic_buf, disasm.operands_buf);

            last_instr_len = pos - start_pos;
            return &disasm;
        }

        if (bytes[pos] >= 0xB0 && bytes[pos] <= 0xB7) {

            uint8_t opcode = bytes[pos++];
            uint8_t reg_no = opcode - 0xB0;
            uint8_t imm = bytes[pos++];

            const char *reg;

            if (is_rex) {
                if (rex.b)
                    reg_no += 8;

                reg = regs8_rex[reg_no];
            }
            else {
                reg = regs8_legacy[reg_no];
            }

            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "mov");
            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, 0x%x", reg, imm);
            snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD "%-10s" WHITE "%s", disasm.mnemonic_buf, disasm.operands_buf);

            last_instr_len = pos - start_pos;
            return &disasm;
        }

        if (bytes[pos] >= 0xB8 && bytes[pos] <= 0xBF) {
            uint8_t opcode = bytes[pos++];
            uint8_t reg_no = opcode - 0xB8;
            uint64_t imm;
            const char *reg;

            if (rex.b)
                reg_no += 8;
            if (rex.w) {
                imm = *(uint64_t *)&bytes[pos];
                reg = regs64[reg_no];
                pos += 8;
            }
            else {
                imm = *(uint32_t *)&bytes[pos];
                reg = regs32[reg_no];
                pos += 4;
            }

            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "mov");

            if (rex.w)
                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, 0x%016llx", reg, imm);
            else
                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, 0x%08x", reg, imm);

            snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD "%-10s" WHITE "%s", disasm.mnemonic_buf, disasm.operands_buf);

            last_instr_len = pos - start_pos;
            return &disasm;
        }

        if ((current = search(rex_opcodes, (sizeof(rex_opcodes) / sizeof(rex_opcodes[0])), (uint16_t)bytes[pos++])) == NULL) // if an instruction is REX pos = 1, will be = 2,  if not pos = 0, will be = 1
            return &disasm;

        char *size_str = current->operand_size;
        char *ptr_str = "PTR";

        if (!strcmp(current->mnemonic, "lea")) {
            size_str = current->operand_size ? current->operand_size : "";
            ptr_str = "";
        }

        char *regs_data[16];
        char *regs_addr[16];

        memcpy(regs_addr, regs64, sizeof(regs64));

        if (rex.w)
            memcpy(regs_data, regs64, sizeof(regs64));
        else
            memcpy(regs_data, regs32, sizeof(regs32));

        if (current != NULL) {
            // if instruction is not in the group
            if (strcmp(current->mnemonic, "grp80") 
            && strcmp(current->mnemonic, "grp81") 
            && strcmp(current->mnemonic, "grp83")
            && strcmp(current->mnemonic, "grpC1"))
                snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", current->mnemonic);

            uint8_t modrm = bytes[pos++];
       
            uint8_t mod = ((modrm >> 0x6) & 0x3);
            uint8_t reg = (modrm >> 0x3) & 0x7;
            uint8_t rm = modrm & 0x7;        
            
            uint8_t dst;
            uint8_t src;

            if (!strcmp(current->mnemonic, "grp80") 
            || !strcmp(current->mnemonic, "grp81") 
            || !strcmp(current->mnemonic, "grp83")) {
                char *mnemonic;
                switch(reg) {
                    case 0: mnemonic = "add"; break;
                    case 1: mnemonic = "or";  break;
                    case 4: mnemonic = "and"; break;
                    case 5: mnemonic = "sub"; break;
                    case 6: mnemonic = "xor"; break;
                    case 7: mnemonic = "cmp"; break;
                }
                snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", mnemonic);
            }

            if (!strcmp(current->mnemonic, "grpC1")) {
                char *mnemonic;
                switch(reg) {
                    case 0: mnemonic = "rol"; break;
                    case 1: mnemonic = "ror"; break;
                    case 2: mnemonic = "rcl"; break;
                    case 3: mnemonic = "rcr"; break;
                    case 4: mnemonic = "shl"; break;
                    case 5: mnemonic = "shr"; break;
                    case 7: mnemonic = "sar"; break;
                }
                snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), "%s", mnemonic);
            }

            // all values 'mod' from ModR/M byte can be equal to: 
            // 00 - memory (no displacement)
            // 01 - memory (disp8)
            // 10 - memory (disp32)
            // 11 - both operands are registers
            
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
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s ["PURPLE"0x%08x"WHITE"], %s", size_str, ptr_str, disp, regs_data[src]); 
                                else // no index, base exists                                    
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_data[src]);                                 
                            }
                            else { // index exists
                                if (base == 0x5) // index exists, no base                      
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s * %d + "PURPLE"0x%08x"WHITE"], %s", size_str, ptr_str, regs_addr[index + (rex.x << 0x3)], 1 << ss, disp, regs_data[src]); 
                                else // index exists, base exists
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, regs_data[src]); 
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [rip+"PURPLE"0x%08x"WHITE"], %s", size_str, ptr_str, disp, regs_data[src]);    
                        }                    
                        else {
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s], %s", size_str, ptr_str, regs_addr[dst], regs_data[src]);  
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
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s ["PURPLE"0x%08x"WHITE"]", regs_data[dst], size_str, ptr_str, disp);                          
                                else { // no index, base exists                                    
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)]); 
                                }
                            }
                            else { // index exists
                                if (base == 0x5) { // index exists, no base                                   
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s * %d + "PURPLE"0x%08x"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[index + (rex.x << 0x3)], 1 << ss, disp); 
                                }
                                else { // index exists, base exists
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s + %s * %d]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss); 
                                }
                            }
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [rip+"PURPLE"0x%08x"WHITE"]", regs_data[dst], size_str, ptr_str, disp); 
                        }
                        else
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s]", regs_data[dst], size_str, ptr_str, regs_addr[src]); 
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
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s ["PURPLE"0x%08x"WHITE"], %+d", size_str, ptr_str, disp, imm);
                                else
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s], %+d", size_str, ptr_str, regs_addr[base + (rex.b << 3)], imm);
                            }
                            else {
                                if (base == 0x5)
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s * %d + "PURPLE"0x%08x"WHITE"], %+d", size_str, ptr_str, regs_addr[index + (rex.x << 3)], 1 << ss, disp, imm);
                                else {
                                    snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d], %+d", size_str, ptr_str, regs_addr[base + (rex.b << 3)], regs_addr[index + (rex.x << 3)], 1 << ss, imm);
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [rip+"PURPLE"0x%08x"WHITE"], %+d", size_str, ptr_str, disp, imm);
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s], %+d", size_str, ptr_str, regs_addr[dst], imm);
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp, regs_data[src]); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d "PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp, regs_data[src]); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp, regs_data[src]);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[dst], disp, regs_data[src]); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s + %s * %d "PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int8_t disp = (int8_t)bytes[pos++];
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[src], disp); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s%"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d "PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp, imm);  
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
                            
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[dst], disp, imm); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp, regs_data[src]); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d "PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp, regs_data[src]); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp, regs_data[src]);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], %s", size_str, ptr_str, regs_addr[dst], disp, regs_data[src]); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s  [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s  [%s + %s * %d "PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp); 
                        }
                        else if (rm == 0x5) {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s  [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp);  
                        }
                        else {
                            int32_t disp = *(int32_t *)&bytes[pos];
                            pos += 4;
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"]", regs_data[dst], size_str, ptr_str, regs_addr[src], disp); 
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
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s  [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], disp, imm); 
                            else
                                snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s + %s * %d "PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[base + (rex.b << 0x3)], regs_addr[index + (rex.x << 0x3)], 1 << ss, disp, imm); 
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

                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s  [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[5 + (rex.b << 0x3)], disp, imm);  
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
                            
                            snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), BLUE"%s"WHITE" %s [%s"PURPLE"%+d"WHITE"], "PURPLE"%+d"WHITE, size_str, ptr_str, regs_addr[dst], disp, imm); 
                        }
                    }
                break;
                case 0x3: // both operands are registers (or one of them is imm)
                    if (current->order == RM_REG) {
                        dst = rex.b ? rm + 8 : rm;
                        src = rex.r ? reg + 8 : reg;                      
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, %s", regs_data[dst], regs_data[src]);  
                    }
                    else if (current->order == REG_RM) {            
                        dst = rex.r ? reg + 8 : reg;
                        src = rex.b ? rm + 8 : rm;
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, %s", regs_data[dst], regs_data[src]);
                    }
                    else if (current->order == RM_IMM) {
                        dst = rex.b ? rm + 8 : rm;
                        snprintf(disasm.operands_buf, sizeof(disasm.operands_buf), "%s, "PURPLE"0x%02x"WHITE, regs_data[dst], bytes[pos++]);  
                    }             
                break;
            }   
            snprintf(disasm.disasm_buf, sizeof(disasm.disasm_buf), GOLD"%-10s"WHITE"%s", disasm.mnemonic_buf, disasm.operands_buf);
            last_instr_len = pos - start_pos;
            return &disasm;
        }
        else {
            snprintf(disasm.mnemonic_buf, sizeof(disasm.mnemonic_buf), RED"UNKNOWN"WHITE);
            last_instr_len = pos - start_pos;
            return &disasm;
        }
    }
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

                    //if (history[j].instruction.mnemonic_buf[0] == '\0')
                    //    continue;

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
