#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

int main() {
    size_t length = 256 * 1024 * 1024; // 256 MB
    // mmap anonymous private
    void *addr = mmap(NULL, length, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("Allocated %zu bytes at %p\n", length, addr);

    // Touch the memory to actually allocate pages
    memset(addr, 0, length);

    // Advise kernel to use transparent huge pages
    if (madvise(addr, length, MADV_HUGEPAGE) != 0) {
        perror("madvise");
        munmap(addr, length);
        return 1;
    }

    printf("Called madvise with MADV_HUGEPAGE\n");

    while (true)
    {
    }
    

    munmap(addr, length);
    return 0;
}
