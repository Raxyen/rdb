#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define PURPLE  "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

enum operand_order {
    REG_RM,
    RM_REG,
    RM_IMM
};

struct stack_val {
    long val;
    long addr;
};

struct instruction {
    uint16_t opcode;
    const char *mnemonic;
    int length;
    enum operand_order order;
};

struct rex_prefix {
    int w;
    int r;
    int x;
    int b;
};

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

struct instruction *search(struct instruction *set, uint16_t opcode) {
    for (size_t i = 0; i < sizeof(*set); i++) {
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


void disassemble(unsigned char *bytes) {
    struct instruction *current;

    // used if bytes[0] != 0x48 
    struct instruction opcodes[] = { 
        {0x90, "nop", 1},
        {0xC3, "ret", 1},
        {0xCC, "int3", 1},

        {0x55, "push rbp", 1},
        {0x5D, "pop rbp", 1},

        {0x74, "je", 2}, // je rel8
        {0x75, "jne", 2}, // jne rel8
        {0x76, "jbe", 2}, // jbe rel8
        {0x77, "ja", 2}, // ja rel8

        {0xEB, "jmp", 2}, // jmp rel8

        {0xE8, "call", 5}, // call rel32
        {0xE9, "jmp", 5} // jmp rel32
    };

    struct instruction rex_opcodes[] = {
        {0x88, "mov",  -1, RM_REG},   // mov r/m8, r8
        {0x89, "mov",  -1, RM_REG},   // mov r/m64, r64

        {0x8B, "mov",  -1, REG_RM},   // mov r64, r/m64

        {0xC7, "mov",  -1, RM_IMM},   // mov r/m64, imm32

        // {0x83, "add",   4, RM_IMM},   // add r/m64, imm8

        {0x01, "add",   3, RM_REG},   // add r/m64, r64
        {0x03, "add",   3, REG_RM},   // add r64, r/m64

        {0x8D, "lea",  -1, REG_RM},   // lea r64, m

        {0x85, "test", -1, RM_REG},   // test r/m64, r64

        {0x83, "grp83",-1, RM_IMM}    // add/sub/cmp r/m64, imm8
};

    if (isRex(bytes[0])) { // executed if first byte of an instruction is REX
        const char *regs64[16] = { 
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        };
        
        struct rex_prefix rex = parseRex(bytes[0]);
        current = search(rex_opcodes, (uint16_t)(bytes[1]));
        if (current != NULL) {
            printf("%s", current->mnemonic);
            uint8_t modrm = bytes[2];

            uint8_t dst_reg_no;
            uint8_t src_reg_no;

            if (((modrm >> 6) & 0x3) == 0x3) {
                if (current->order == RM_REG) {
                    dst_reg_no = rex.b ? (modrm & 0x7) + 8 : modrm & 0x7;
                    src_reg_no = rex.r ? (((modrm >> 0x3) & 0x7) + 8) : ((modrm >> 0x3) & 0x7);                      
                    printf("    %s, %s", regs64[dst_reg_no], regs64[src_reg_no]);  
                }
                else if (current->order == REG_RM) {            
                    dst_reg_no = rex.r ? (((modrm >> 0x3) & 0x7) + 8) : ((modrm >> 0x3) & 0x7);
                    src_reg_no = rex.b ? (modrm & 0x7) + 8 : modrm & 0x7;
                    printf("    %s, %s", regs64[dst_reg_no], regs64[src_reg_no]);  
                }
                else if (current->order == RM_IMM) {
                    dst_reg_no = rex.b ? (modrm & 0x7) + 8 : modrm & 0x7;
                    printf("    %s, 0x%02x", regs64[dst_reg_no], bytes[3]);  
                }             
            }
        }
        else {
            printf(RED"UNKNOWN"WHITE);
        }
    }
    else { // executed otherwise (not REX)
        current = search(opcodes, (uint16_t)(bytes[0]));
        if (current != NULL)
            printf("%s", current->mnemonic);
        else {
            printf(RED"UNKNOWN"WHITE);
        }
    }
}

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
            struct user_regs_struct regs, prev_regs;
            struct stack_val stack_arr[8];
            
            for (size_t i = 0; i < number_of_instructions; i++) {
                ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                waitpid(pid, &status, 0);
                WSTOPSIG(status);               
                              
                ptrace(PTRACE_GETREGS, pid, NULL, &regs); // get registers   
                 
                if (i == 0)
                    prev_regs = regs;

                printf("\033[2J");
                printf("\033[H");

                printRegs(&regs, &prev_regs);           

                for (size_t j = 0; j < 8; j++) {
                    stack_arr[j].val = ptrace(PTRACE_PEEKDATA, pid, (void *)(regs.rsp + j * 8), NULL);
                    stack_arr[j].addr = regs.rsp + j * 8;
                }

                printStack(stack_arr, &regs, 8);

                long value = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);
                printf(CYAN" ════════════════════════════════════════════════════════\n"WHITE);
                unsigned char *bytes = (unsigned char *)&value;

                printf("0x%016lx: ", regs.rip); // instruction pointer

                // 8 raw bytes starting off the address instruction pointer points to
                for (int i = 0; i < 8; i++) {
                    printf("%02x ", bytes[i]);
                }
            
                printf(" | ");
                disassemble(bytes);
                printf("\n");

                prev_regs = regs;

                usleep(100000);
            }
        }
    }

    return 0;
}
