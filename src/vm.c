#include "vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>

// Forward declarations for JIT functions
int jit_compile_sbf(uint8_t *code, size_t size, void **jit_code, size_t *jit_size);
void jit_execute(solana_vm_t *vm, uint64_t entrypoint);

// Helper function to align values
static inline size_t align_up(size_t value, size_t alignment) {
    return ((value + alignment - 1) / alignment) * alignment;
}

// Create a new VM instance
solana_vm_t *create_vm(size_t memory_size) {
    solana_vm_t *vm = (solana_vm_t *)calloc(1, sizeof(solana_vm_t));
    if (!vm) {
        fprintf(stderr, "Failed to allocate VM\n");
        return NULL;
    }
    
    // Align memory size to page size
    memory_size = align_up(memory_size, SBF_PAGE_SIZE);
    
    // Allocate memory for program
    vm->memory = (uint8_t *)mmap(NULL, memory_size, 
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (vm->memory == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        free(vm);
        return NULL;
    }
    
    // Initialize memory to zero
    memset(vm->memory, 0, memory_size);
    vm->memory_size = memory_size;
    
    // Allocate stack
    vm->stack_size = SBF_STACK_SIZE;
    vm->stack = (uint64_t *)calloc(vm->stack_size / sizeof(uint64_t), 1);
    if (!vm->stack) {
        munmap(vm->memory, vm->memory_size);
        free(vm);
        return NULL;
    }
    
    // Allocate return value
    vm->return_value = (uint64_t *)calloc(1, sizeof(uint64_t));
    if (!vm->return_value) {
        free(vm->stack);
        munmap(vm->memory, vm->memory_size);
        free(vm);
        return NULL;
    }
    
    return vm;
}

// Destroy VM and free resources
void destroy_vm(solana_vm_t *vm) {
    if (vm) {
        if (vm->memory && vm->memory != MAP_FAILED) {
            munmap(vm->memory, vm->memory_size);
        }
        free(vm->stack);
        free(vm->return_value);
        free(vm);
    }
}

// Load ELF into VM memory
int load_elf_into_vm(solana_vm_t *vm, const uint8_t *elf_data, size_t elf_size) {
    if (!vm || !elf_data || elf_size < sizeof(Elf64_Ehdr)) {
        return -1;
    }
    
    // Verify ELF magic
    if (elf_data[0] != ELFMAG0 || 
        elf_data[1] != ELFMAG1 || 
        elf_data[2] != ELFMAG2 || 
        elf_data[3] != ELFMAG3) {
        fprintf(stderr, "Invalid ELF magic\n");
        return -1;
    }
    
    // Verify 64-bit little-endian
    if (elf_data[EI_CLASS] != ELFCLASS64 || 
        elf_data[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "Only 64-bit little-endian ELF supported\n");
        return -1;
    }
    
    // Cast to ELF header
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;
    
    // Verify BPF architecture
    if (ehdr->e_machine != 263) {
        fprintf(stderr, "Not a BPF ELF file\n");
        return -1;
    }
    
    // Get section headers
    const Elf64_Shdr *shdr = (const Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    const char *shstrtab = (const char *)(elf_data + shdr[ehdr->e_shstrndx].sh_offset);
    
    // Process each section
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = shstrtab + shdr[i].sh_name;
        
        // Skip empty sections
        if (shdr[i].sh_type == SHT_NULL) continue;
        
        // Process .text section (executable code)
        if (strcmp(section_name, ".text") == 0) {
            if (shdr[i].sh_offset + shdr[i].sh_size > elf_size) {
                fprintf(stderr, "Text section out of bounds\n");
                return -1;
            }
            
            // Copy text section to memory
            memcpy(vm->memory + shdr[i].sh_addr, 
                   elf_data + shdr[i].sh_offset, 
                   shdr[i].sh_size);
            
            // Make text section executable
            if (mprotect(vm->memory + shdr[i].sh_addr, 
                        shdr[i].sh_size, 
                        PROT_READ | PROT_EXEC) != 0) {
                fprintf(stderr, "Warning: Failed to make text section executable: %s\n", 
                        strerror(errno));
            }
        }
        // Process .rodata section (read-only data)
        else if (strcmp(section_name, ".rodata") == 0) {
            if (shdr[i].sh_offset + shdr[i].sh_size > elf_size) {
                fprintf(stderr, "ROData section out of bounds\n");
                return -1;
            }
            
            // Copy rodata section to memory
            memcpy(vm->memory + shdr[i].sh_addr, 
                   elf_data + shdr[i].sh_offset, 
                   shdr[i].sh_size);
            
            // Make read-only
            if (mprotect(vm->memory + shdr[i].sh_addr, 
                        shdr[i].sh_size, 
                        PROT_READ) != 0) {
                fprintf(stderr, "Warning: Failed to make rodata section read-only: %s\n", 
                        strerror(errno));
            }
        }
        // Process .bss section (uninitialized data)
        else if (strcmp(section_name, ".bss") == 0) {
            // BSS is already zeroed by calloc, but ensure it's writable
            if (mprotect(vm->memory + shdr[i].sh_addr, 
                        shdr[i].sh_size, 
                        PROT_READ | PROT_WRITE) != 0) {
                fprintf(stderr, "Warning: Failed to make bss section writable: %s\n", 
                        strerror(errno));
            }
        }
    }
    
    return 0;
}

// JIT compile SBF to native code (simplified example)
// In production, you'd use a proper JIT compiler like LLVM or a custom SBF JIT
int jit_compile_sbf(uint8_t *code, size_t size, void **jit_code, size_t *jit_size) {
    // For this example, we'll just copy the code to executable memory
    // In a real implementation, you'd parse the BPF instructions and generate native code
    
    // Round up size to page boundary
    *jit_size = align_up(size, SBF_PAGE_SIZE);
    
    // Allocate executable memory
    *jit_code = mmap(NULL, *jit_size, 
                    PROT_READ | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*jit_code == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate JIT memory: %s\n", strerror(errno));
        return -1;
    }
    
    // Copy code to JIT memory
    memcpy(*jit_code, code, size);
    
    return 0;
}

// Execute program in VM (simplified - in production you'd use proper JIT)
void execute_vm(solana_vm_t *vm, uint64_t entrypoint) {
    // Set up registers (simplified)
    // In Solana, registers are mapped as:
    // r0 = return value (x10)
    // r1-r5 = arguments (x11-x15)
    // r6-r9 = callee-saved (x8-x9, x1, x2)
    // r10 = frame pointer (x3)
    // r11 = program counter (x12)
    
    // Set up stack pointer (r10)
    vm->regs.r[10] = (uint64_t)(vm->stack + vm->stack_size / sizeof(uint64_t));
    
    // Set up entrypoint
    vm->regs.r[11] = entrypoint;
    
    // Print debug info
    printf("Executing program at entrypoint: 0x%lx\n", entrypoint);
    printf("Stack pointer: 0x%lx\n", vm->regs.r[10]);
    
    // In a real implementation, you would:
    // 1. JIT compile the SBF to native code
    // 2. Set up the execution environment
    // 3. Call the JITed code
    // 4. Handle the return
    
    // For this example, we'll simulate execution
    printf("Program execution simulated\n");
    
    // In a real implementation, you'd call the JITed code like:
    // typedef int (*program_entry_t)(solana_vm_t *);
    // program_entry_t entry = (program_entry_t)vm->jit_code;
    // int result = entry(vm);
    
    // For now, just return success
    printf("Program execution completed\n");
}

// Main function demonstrating the complete flow
// int main(int argc, char *argv[]) {
//     if (argc < 2) {
//         fprintf(stderr, "Usage: %s <elf_file> [entrypoint_offset]\n", argv[0]);
//         return 1;
//     }
//     
//     const char *elf_file = argv[1];
//     uint64_t entrypoint_offset = (argc > 2) ? strtoull(argv[2], NULL, 10) : 288;
//     
//     // Read ELF file
//     FILE *fp = fopen(elf_file, "rb");
//     if (!fp) {
//         fprintf(stderr, "Failed to open ELF file: %s\n", elf_file);
//         return 1;
//     }
//     
//     // Get file size
//     fseek(fp, 0, SEEK_END);
//     size_t elf_size = ftell(fp);
//     fseek(fp, 0, SEEK_SET);
//     
//     // Allocate buffer for ELF data
//     uint8_t *elf_data = (uint8_t *)malloc(elf_size);
//     if (!elf_data) {
//         fprintf(stderr, "Failed to allocate buffer for ELF data\n");
//         fclose(fp);
//         return 1;
//     }
//     
//     // Read ELF data
//     if (fread(elf_data, 1, elf_size, fp) != elf_size) {
//         fprintf(stderr, "Failed to read ELF data\n");
//         free(elf_data);
//         fclose(fp);
//         return 1;
//     }
//     fclose(fp);
//     
//     // Create VM
//     solana_vm_t *vm = create_vm(1024 * 1024);  // 1MB memory
//     if (!vm) {
//         fprintf(stderr, "Failed to create VM\n");
//         free(elf_data);
//         return 1;
//     }
//     
//     // Load ELF into VM
//     if (load_elf_into_vm(vm, elf_data, elf_size) != 0) {
//         fprintf(stderr, "Failed to load ELF into VM\n");
//         destroy_vm(vm);
//         free(elf_data);
//         return 1;
//     }
//     
//     // JIT compile if possible (optional)
//     // In a real implementation, you'd do this before execution
//     // int jit_result = jit_compile_sbf(vm->memory, vm->memory_size, &vm->jit_code, &vm->jit_size);
//     // if (jit_result != 0) {
//     //     fprintf(stderr, "JIT compilation failed\n");
//     //     destroy_vm(vm);
//     //     free(elf_data);
//     //     return 1;
//     // }
//     
//     // Execute program
//     printf("Executing program with entrypoint at offset %lu\n", entrypoint_offset);
//     execute_program(vm, entrypoint_offset);
//     
//     // Cleanup
//     // if (vm->jit_code && vm->jit_code != MAP_FAILED) {
//     //     munmap(vm->jit_code, vm->jit_size);
//     // }
//     destroy_vm(vm);
//     free(elf_data);
//     
//     return 0;
// }
