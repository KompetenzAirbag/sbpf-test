#pragma once

#include <stdint.h>
#include <string.h>

// Constants for Solana SBF
#define SBF_PAGE_SIZE 4096
#define SBF_STACK_SIZE 8192  // 8KB stack
#define SBF_MAX_REGISTERS 12

// Solana SBF registers (mapped to x10-x15, x8, x9, x1, x2, x3 in RISC-V)
typedef struct {
    uint64_t r[SBF_MAX_REGISTERS];  // r0-r11 (x10-x15, x8, x9, x1, x2, x3)
} solana_registers_t;

// Solana context structure
typedef struct {
    uint8_t *memory;           // Program memory
    size_t memory_size;
    uint64_t *stack;           // Program stack
    size_t stack_size;
    solana_registers_t regs;   // Registers
    uint64_t *return_value;    // Return value pointer
    void *jit_code;            // JIT compiled code (if applicable)
    size_t jit_size;
} solana_vm_t;

solana_vm_t *create_vm(size_t memory_size);

int load_elf_into_vm(solana_vm_t *vm, const uint8_t *elf_data, size_t elf_size);

void destroy_vm(solana_vm_t *vm);

void execute_vm(solana_vm_t *vm, uint64_t entrypoint);
