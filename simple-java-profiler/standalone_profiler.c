/*
 * 独立的Java性能分析工具
 * 使用perf_event直接采样，无需注入JVMTI agent
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>

#define BUFFER_SIZE 4096
#define MAX_STACK_DEPTH 64
#define SAMPLE_FREQ 99
#define DEFAULT_DURATION 10

static volatile int running = 1;

typedef struct {
    unsigned long start;
    unsigned long end;
    char* name;
} MemoryRegion;

MemoryRegion regions[256];
int region_count = 0;

typedef struct {
    unsigned long ip;
} StackSample;

StackSample samples[65536];
int sample_count = 0;

typedef struct {
    char** stacks;
    int count;
} StackHashEntry;

#define HASH_SIZE 10007
StackHashEntry hash_table[HASH_SIZE];

static void signal_handler(int sig) {
    running = 0;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                          int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int read_proc_maps(pid_t pid) {
    char filename[256];
    FILE* fp;
    char line[BUFFER_SIZE];
    
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    
    fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open /proc/maps");
        return -1;
    }
    
    region_count = 0;
    while (fgets(line, sizeof(line), fp) && region_count < 256) {
        char* ptr = line;
        while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n') {
            ptr++;
        }
        if (*ptr) {
            regions[region_count].name = NULL;
            regions[region_count].start = strtoul(line, NULL, 16);
            char* end_ptr = strchr(line, '-');
            if (end_ptr) {
                regions[region_count].end = strtoul(end_ptr + 1, NULL, 16);
            }
            
            char* path_ptr = strrchr(line, '\t');
            if (!path_ptr) {
                path_ptr = strrchr(line, ' ');
            }
            if (path_ptr && *(path_ptr + 1)) {
                regions[region_count].name = strdup(path_ptr + 1);
                char* newline = strchr(regions[region_count].name, '\n');
                if (newline) {
                    *newline = '\0';
                }
            }
            
            region_count++;
        }
    }
    
    fclose(fp);
    return 0;
}

static const char* find_symbol(unsigned long ip) {
    static char buffer[256];
    
    for (int i = 0; i < region_count; i++) {
        if (ip >= regions[i].start && ip < regions[i].end) {
            if (regions[i].name) {
                return regions[i].name;
            }
            return "unknown";
        }
    }
    snprintf(buffer, sizeof(buffer), "0x%lx", ip);
    return buffer;
}

static unsigned int hash_stack(unsigned long* stack, int depth) {
    unsigned int hash = 0;
    for (int i = 0; i < depth; i++) {
        hash ^= (unsigned int)stack[i];
        hash = (hash << 13) | (hash >> 19);
    }
    return hash % HASH_SIZE;
}

static void add_sample(unsigned long* stack, int depth) {
    if (sample_count < (int)(sizeof(samples) / sizeof(samples[0]))) {
        samples[sample_count].ip = stack[0];
        sample_count++;
    }
    
    unsigned int h = hash_stack(stack, depth);
    int found = 0;
    
    for (int i = 0; i < hash_table[h].count; i++) {
        int match = 1;
        char** s = hash_table[h].stacks;
        for (int j = 0; j < depth; j++) {
            if (stack[j] != 0 || s[j] != NULL) {
                match = 0;
                break;
            }
        }
        if (match) {
            found = 1;
            break;
        }
    }
    
    if (!found) {
        int new_count = hash_table[h].count + 1;
        char** new_stacks = realloc(hash_table[h].stacks, new_count * sizeof(char*));
        if (new_stacks) {
            hash_table[h].stacks = new_stacks;
            hash_table[h].stacks[hash_table[h].count] = malloc(depth * 256);
            hash_table[h].count = new_count;
        }
    }
}

static int sample_loop(int fd, pid_t target_pid, int duration) {
    void* mmap_ptr;
    struct perf_event_mmap_page* header;
    size_t mmap_size = (1 + 16) * getpagesize();
    
    mmap_ptr = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mmap_ptr == MAP_FAILED) {
        perror("mmap failed");
        return -1;
    }
    header = (struct perf_event_mmap_page*)mmap_ptr;
    
    time_t start_time = time(NULL);
    
    while (running && (time(NULL) - start_time) < duration) {
        unsigned long* data_tail = header->data_tail;
        unsigned long* data_head = header->data_head;
        
        if (data_tail == data_head) {
            usleep(10000);
            continue;
        }
        
        struct perf_event_header* event = (struct perf_event_header*)((char*)mmap_ptr + (data_tail % mmap_size));
        if (event->type == PERF_RECORD_SAMPLE) {
            unsigned long* ptr = (unsigned long*)(event + 1);
            unsigned long ip = 0;
            unsigned long stack[MAX_STACK_DEPTH];
            int stack_depth = 0;
            
            if (event->misc & PERF_RECORD_MISC_USER) {
                ip = *ptr++;
                unsigned long ustack_size = *ptr++;
                for (int i = 0; i < (int)(ustack_size / sizeof(unsigned long)); i++) {
                    stack[stack_depth++] = *ptr++;
                }
                add_sample(stack, stack_depth);
            }
        }
        
        header->data_tail = data_tail + event->size;
    }
    
    munmap(mmap_ptr, mmap_size);
    return 0;
}

static void print_results() {
    FILE* fp = fopen("profiler.folded", "w");
    if (!fp) {
        perror("Failed to open output file");
        return;
    }
    
    for (int i = 0; i < HASH_SIZE; i++) {
        for (int j = 0; j < hash_table[i].count; j++) {
            fprintf(fp, "stack_%d %d\n", i, 1);
        }
    }
    
    fclose(fp);
    printf("Generated %d samples. Output written to profiler.folded\n", sample_count);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [duration]\n", argv[0]);
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    int duration = (argc > 2) ? atoi(argv[2]) : DEFAULT_DURATION;
    
    printf("Target PID: %d, duration: %d seconds\n", target_pid, duration);
    
    if (read_proc_maps(target_pid)) {
        return 1;
    }
    printf("Read %d memory regions\n", region_count);
    
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_period = 1000000 / SAMPLE_FREQ;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_TID;
    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    
    int fd = perf_event_open(&pe, target_pid, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        printf("Error: You may need to run as root or adjust /proc/sys/kernel/perf_event_paranoid\n");
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1) {
        perror("ioctl reset failed");
        close(fd);
        return 1;
    }
    
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        perror("ioctl enable failed");
        close(fd);
        return 1;
    }
    printf("Profiler started. Press Ctrl+C to stop.\n");
    
    sample_loop(fd, target_pid, duration);
    
    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        perror("ioctl disable failed");
    }
    
    close(fd);
    print_results();
    
    for (int i = 0; i < region_count; i++) {
        if (regions[i].name) {
            free(regions[i].name);
        }
    }
    
    return 0;
}
