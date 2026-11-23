#include "vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <errno.h>
#include <libbase64.h>  // You'll need a base64 implementation
#include <math.h>
#include <elf.h>

// Constants for SBF program alignment
#define SBF_ALIGN 16
#define SBF_PAGE_SIZE 4096

typedef struct __attribute__((packed)) {
    uint32_t version;
    uint64_t slot;     // Deployment slot
    uint8_t  accounts;
    uint8_t  account[32];
    // Followed by the actual ELF binary data
} solana_program_data_header_t;

// Simple memory manager for our simulated environment
typedef struct {
    uint8_t *memory;
    size_t size;
} solana_memory_t;

// Program metadata structure
typedef struct {
    uint64_t text_offset;
    uint64_t text_size;
    uint64_t rodata_offset;
    uint64_t rodata_size;
    uint64_t bss_size;
    uint64_t entrypoint;
} solana_program_info_t;

// Simulated Solana context (simplified)
typedef struct {
    solana_memory_t *memory;
    uint64_t *stack;
    uint64_t *return_value;
} solana_context_t;

// Forward declarations for our simulated runtime
solana_memory_t *create_memory(size_t size);
void destroy_memory(solana_memory_t *mem);
int load_program_data(solana_memory_t *mem, const char *base64_data, solana_program_info_t *info);
int execute_program(solana_program_info_t *info, solana_context_t *ctx);

char *_base64_decode(const char *input, size_t *out_len) {
    size_t in_len = strlen( input );
    char* out = malloc( 4*ceil(((double)in_len/3)) );
    if( out == NULL ) return NULL;

    base64_decode( input, in_len, out, out_len, 0 );
    return out;
}

// Create memory region for the program
solana_memory_t *create_memory(size_t size) {
    // Align size to SBF_ALIGN
    size = ((size + SBF_ALIGN - 1) / SBF_ALIGN) * SBF_ALIGN;
    
    // Allocate memory with page alignment for better simulation
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        return NULL;
    }
    
    solana_memory_t *result = (solana_memory_t *)malloc(sizeof(solana_memory_t));
    if (!result) {
        munmap(mem, size);
        return NULL;
    }
    
    result->memory = (uint8_t *)mem;
    result->size = size;
    
    // Initialize memory to zero
    memset(result->memory, 0, size);
    
    return result;
}

// Free memory region
void destroy_memory(solana_memory_t *mem) {
    if (mem) {
        if (mem->memory) {
            munmap(mem->memory, mem->size);
        }
        free(mem);
    }
}

// Function to parse ELF header and extract program information
int parse_elf_header(const uint8_t *elf_data, size_t elf_size, solana_program_info_t *info) {
    if (!elf_data || !info) {
        return -1;
    }
    
    // Check minimum size for ELF header
    if (elf_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "ELF data too small for header\n");
        return -1;
    }
    
    // Verify ELF magic number
    if (elf_data[0] != ELFMAG0 || 
        elf_data[1] != ELFMAG1 || 
        elf_data[2] != ELFMAG2 || 
        elf_data[3] != ELFMAG3) {
        fprintf(stderr, "Invalid ELF magic number\n");
        return -1;
    }
    
    // Verify ELF class (64-bit)
    if (elf_data[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Only 64-bit ELF files are supported\n");
        return -1;
    }
    
    // Verify endianness (little-endian)
    if (elf_data[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "Only little-endian ELF files are supported\n");
        return -1;
    }
    
    // Verify ELF version
    if (elf_data[EI_VERSION] != EV_CURRENT) {
        fprintf(stderr, "Unsupported ELF version\n");
        return -1;
    }
    
    // Cast to ELF header structure
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;
    
    // Verify it's an executable or shared object
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) {
        fprintf(stderr, "Not an executable ELF file (type: %d)\n", ehdr->e_type);
        return -1;
    }
    
    // Verify architecture (BPF for Solana)
    if (ehdr->e_machine != 263) {
        fprintf(stderr, "Not a BPF ELF file (machine type: %d)\n", ehdr->e_machine);
        return -1;
    }
    
    // Initialize info structure
    memset(info, 0, sizeof(solana_program_info_t));
    
    // Get section header string table index
    if (ehdr->e_shstrndx == SHN_UNDEF) {
        fprintf(stderr, "No section header string table\n");
        return -1;
    }
    
    // Get section headers
    const Elf64_Shdr *shdr = (const Elf64_Shdr *)(elf_data + ehdr->e_shoff);
    
    // Find .text section
    const char *shstrtab = (const char *)(elf_data + shdr[ehdr->e_shstrndx].sh_offset);
    
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = shstrtab + shdr[i].sh_name;
        
        // Process .text section (executable code)
        if (strcmp(section_name, ".text") == 0) {
            info->text_offset = shdr[i].sh_offset;
            info->text_size = shdr[i].sh_size;
            info->entrypoint = shdr[i].sh_addr;  // Virtual address of entrypoint
        }
        // Process .rodata section (read-only data)
        else if (strcmp(section_name, ".rodata") == 0) {
            info->rodata_offset = shdr[i].sh_offset;
            info->rodata_size = shdr[i].sh_size;
        }
        // Process .bss section (uninitialized data)
        else if (strcmp(section_name, ".bss") == 0) {
            info->bss_size = shdr[i].sh_size;
        }
    }
    
    // If no .text section found, try to use entrypoint from ELF header
    if (info->text_size == 0) {
        fprintf(stderr, "No .text section found, using entrypoint from ELF header\n");
        info->entrypoint = ehdr->e_entry;
        info->text_offset = 0;  // Assume code starts at beginning
        info->text_size = elf_size;
    }
    
    // Validate extracted information
    if (info->text_offset + info->text_size > elf_size) {
        fprintf(stderr, "Text section extends beyond ELF data\n");
        return -1;
    }
    
    return 0;
}

// Updated load_program_data function that uses the ELF parser
int load_program_data(solana_memory_t *mem, const char *base64_data, solana_program_info_t *info) {
    if (!mem || !base64_data || !info) {
        return -1;
    }
    
    // Decode base64 data
    size_t decoded_len = 0;
    uint8_t *decoded_data = (uint8_t *)_base64_decode(base64_data, &decoded_len);
    if (!decoded_data) {
        fprintf(stderr, "Failed to decode base64 data\n");
        return -1;
    }
    
    
    // Check minimum size for Solana program data header
    if (decoded_len < sizeof(solana_program_data_header_t)) {
        fprintf(stderr, "Decoded data too small for Solana program data header\n");
        free(decoded_data);
        return -1;
    }
    
    // Parse Solana program data header
    solana_program_data_header_t *pdata = (solana_program_data_header_t *)decoded_data;
    
    // Verify version (should be 3 for current format)
    if (pdata->version != 3) {
        fprintf(stderr, "Unsupported program data version: %u\n", pdata->version);
        free(decoded_data);
        return -1;
    }
    
    // The actual ELF binary starts after the header
    uint8_t *elf_data = decoded_data + sizeof(solana_program_data_header_t);
    size_t elf_size = decoded_len - sizeof(solana_program_data_header_t);

    // Now parse the ELF header from the extracted data
    if (parse_elf_header(elf_data, elf_size, info) != 0) {
        fprintf(stderr, "Failed to parse ELF header from program data\n");
        free(decoded_data);
        return -1;
    }
    
    // Validate that the ELF fits in our memory
    size_t required_size = info->text_offset + info->text_size + info->rodata_size + info->bss_size;
    if (required_size > mem->size) {
        fprintf(stderr, "Program too large for allocated memory\n");
        free(decoded_data);
        return -1;
    }

    memcpy( mem->memory, elf_data, elf_size );
    mem->size = elf_size;
    
    // Copy the ELF sections to memory
    // Text section
    // if (info->text_size > 0 && info->text_offset + info->text_size <= elf_size) {
    //     memcpy(mem->memory + info->text_offset, 
    //            elf_data + info->text_offset, 
    //            info->text_size);
    // }
    // 
    // // ROData section
    // if (info->rodata_size > 0 && info->rodata_offset + info->rodata_size <= elf_size) {
    //     memcpy(mem->memory + info->rodata_offset, 
    //            elf_data + info->rodata_offset, 
    //            info->rodata_size);
    // }
    // 
    // // BSS section (zero-initialized)
    // if (info->bss_size > 0) {
    //     size_t bss_start = info->rodata_offset + info->rodata_size;
    //     memset(mem->memory + bss_start, 0, info->bss_size);
    // }
    
    free(decoded_data);
    return 0;
}

// Simulated execution function
// In a real implementation, this would JIT compile or interpret the SBF
int execute_program(solana_program_info_t *info, solana_context_t *ctx) {
    if (!info || !ctx || !ctx->memory) {
        return -1;
    }
    
    // This is a simplified simulation - in reality, you'd need a full SBF JIT or interpreter
    // For demonstration, we'll just simulate execution by calling a function pointer
    
    // Get the entrypoint address
    // uint8_t *entrypoint = ctx->memory->memory + info->entrypoint;

    uint8_t* elf_data = ctx->memory->memory;

    solana_vm_t *vm = create_vm(1024 * 1024);  // 1MB memory
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }
    
    // Load ELF into VM
    if (load_elf_into_vm(vm, elf_data, ctx->memory->size) != 0) {
        fprintf(stderr, "Failed to load ELF into VM\n");
        destroy_vm(vm);
        return 1;
    }
    
    // JIT compile if possible (optional)
    // In a real implementation, you'd do this before execution
    // int jit_result = jit_compile_sbf(vm->memory, vm->memory_size, &vm->jit_code, &vm->jit_size);
    // if (jit_result != 0) {
    //     fprintf(stderr, "JIT compilation failed\n");
    //     destroy_vm(vm);
    //     free(elf_data);
    //     return 1;
    // }
    
    // Execute program
    execute_vm(vm, info->entrypoint);
    
    // Cleanup
    // if (vm->jit_code && vm->jit_code != MAP_FAILED) {
    //     munmap(vm->jit_code, vm->jit_size);
    // }
    destroy_vm(vm);
    
    // In a real implementation, you would:
    // 1. JIT compile the SBF to native code
    // 2. Set up the execution environment (registers, stack, etc.)
    // 3. Execute the program
    // 4. Handle the return
    
    return 0;  // Success
}

char*
load_file( char* filename )
{
    char * buffer = 0;
    long length;
    FILE * f = fopen (filename, "rb");

    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length + 1);
        if (buffer) {
            fread (buffer, 1, length, f);
        }
        fclose (f);
        buffer[ length ] = '\0';
    }

    return buffer;
}

// Main function demonstrating the loader
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    
    const char *base64_program_file = argv[1];
    char* base64_program = load_file( argv[1] );
    if( !base64_program ) {
        fprintf(stderr, "Failed to read program data from file\n");
        return 1;
    }
    
    // Create memory for the program (10MB should be enough for most programs)
    solana_memory_t *mem = create_memory(10 * 1024 * 1024);
    if (!mem) {
        fprintf(stderr, "Failed to create memory for program\n");
        free( base64_program );
        return 1;
    }
    
    // Parse program info
    solana_program_info_t program_info;
    memset(&program_info, 0, sizeof(program_info));
    
    if (load_program_data(mem, base64_program, &program_info) != 0) {
        fprintf(stderr, "Failed to load program data\n");
        destroy_memory(mem);
        free( base64_program );
        return 1;
    }
    free( base64_program );
    
    // Create context for execution
    solana_context_t ctx;
    ctx.memory = mem;
    ctx.stack = (uint64_t *)malloc(64 * 1024);  // 64KB stack
    ctx.return_value = (uint64_t *)malloc(sizeof(uint64_t));
    
    if (!ctx.stack || !ctx.return_value) {
        fprintf(stderr, "Failed to allocate context memory\n");
        free(ctx.stack);
        free(ctx.return_value);
        destroy_memory(mem);
        return 1;
    }
    
    // Execute the program
    printf("Executing program...\n");
    int result = execute_program(&program_info, &ctx);
    
    // Cleanup
    free(ctx.stack);
    free(ctx.return_value);
    destroy_memory(mem);
    
    if (result != 0) {
        fprintf(stderr, "Program execution failed with code %d\n", result);
        return 1;
    }
    
    printf("Program executed successfully\n");
    return 0;
}
