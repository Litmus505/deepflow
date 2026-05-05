/*
 * 解析Java符号和perf数据的程序
 * 读取perf map文件并解析perf输出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_SYMBOLS 10000
#define MAX_LINE_LENGTH 1024

typedef struct {
    unsigned long address;
    unsigned long size;
    char* name;
} Symbol;

Symbol symbols[MAX_SYMBOLS];
int symbol_count = 0;

typedef struct {
    char key[MAX_LINE_LENGTH];
    int count;
} StackCount;

#define HASH_SIZE 10007
StackCount stack_table[HASH_SIZE];

static int hash(const char* str) {
    int h = 0;
    while (*str) {
        h = h * 31 + *str;
        str++;
    }
    return h % HASH_SIZE;
}

static void add_stack(const char* stack) {
    int h = hash(stack);
    while (h < HASH_SIZE && stack_table[h].count > 0) {
        if (strcmp(stack_table[h].key, stack) == 0) {
            stack_table[h].count++;
            return;
        }
        h = (h + 1) % HASH_SIZE;
    }
    if (h < HASH_SIZE && stack_table[h].count == 0) {
        strncpy(stack_table[h].key, stack, MAX_LINE_LENGTH - 1);
        stack_table[h].key[MAX_LINE_LENGTH - 1] = '\0';
        stack_table[h].count = 1;
    }
}

static int read_perf_map(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    char line[MAX_LINE_LENGTH];
    symbol_count = 0;
    
    while (fgets(line, sizeof(line), fp) && symbol_count < MAX_SYMBOLS) {
        char* end;
        unsigned long addr = strtoul(line, &end, 16);
        if (addr == 0) continue;
        
        unsigned long size = strtoul(end, &end, 16);
        
        char* name = end;
        while (*name == ' ' || *name == '\t') name++;
        char* new_line = strchr(name, '\n');
        if (new_line) *new_line = '\0';
        
        if (strlen(name) > 0) {
            symbols[symbol_count].address = addr;
            symbols[symbol_count].size = size;
            symbols[symbol_count].name = strdup(name);
            symbol_count++;
        }
    }
    
    fclose(fp);
    return 0;
}

static const char* find_symbol(unsigned long ip) {
    int left = 0, right = symbol_count - 1;
    while (left <= right) {
        int mid = (left + right) / 2;
        if (ip >= symbols[mid].address && 
            ip < symbols[mid].address + symbols[mid].size) {
            return symbols[mid].name;
        } else if (ip < symbols[mid].address) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    static char unknown[256];
    snprintf(unknown, sizeof(unknown), "0x%lx", ip);
    return unknown;
}

static void parse_perf_output(FILE* input) {
    char line[MAX_LINE_LENGTH];
    char current_stack[MAX_LINE_LENGTH];
    int in_stack = 0;
    
    while (fgets(line, sizeof(line), input)) {
        if (strstr(line, "sample")) {
            if (in_stack && current_stack[0]) {
                add_stack(current_stack);
                current_stack[0] = '\0';
            }
            in_stack = 0;
        } else if (strchr(line, ';')) {
            // 处理折叠格式
            char* nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            add_stack(line);
        } else {
            char* ip_str = strtok(line, " \t\n");
            if (ip_str && ip_str[0] == '0' && (ip_str[1] == 'x' || ip_str[1] == 'X')) {
                unsigned long ip = strtoul(ip_str, NULL, 16);
                if (in_stack && current_stack[0]) {
                    strcat(current_stack, ";");
                }
                const char* symbol = find_symbol(ip);
                strncat(current_stack, symbol, MAX_LINE_LENGTH - strlen(current_stack) - 1);
                in_stack = 1;
            }
        }
    }
    
    if (in_stack && current_stack[0]) {
        add_stack(current_stack);
    }
}

static void print_results() {
    FILE* fp = fopen("profiler.folded", "w");
    if (!fp) {
        perror("Failed to open output file");
        return;
    }
    
    int max_stacks = 0;
    int total_samples = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        if (stack_table[i].count > 0) {
            fprintf(fp, "%s %d\n", stack_table[i].key, stack_table[i].count);
            total_samples += stack_table[i].count;
            max_stacks++;
        }
    }
    
    fclose(fp);
    printf("Results saved to profiler.folded\n");
    printf("Unique stacks: %d, total samples: %d\n", max_stacks, total_samples);
}

static void cleanup() {
    for (int i = 0; i < symbol_count; i++) {
        if (symbols[i].name) {
            free(symbols[i].name);
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <perf-map-file> [perf-output]\n", argv[0]);
        fprintf(stderr, "  - perf-map-file: path to /tmp/perf-<pid>.map\n");
        fprintf(stderr, "  - perf-output: optional perf script output file (default stdin)\n");
        return 1;
    }
    
    if (read_perf_map(argv[1])) {
        fprintf(stderr, "Failed to read %s\n", argv[1]);
        return 1;
    }
    printf("Loaded %d symbols\n", symbol_count);
    
    FILE* input = stdin;
    if (argc > 2) {
        input = fopen(argv[2], "r");
        if (!input) {
            perror("Failed to open perf output file");
            return 1;
        }
    }
    
    parse_perf_output(input);
    
    if (input != stdin) {
        fclose(input);
    }
    
    print_results();
    cleanup();
    
    return 0;
}
