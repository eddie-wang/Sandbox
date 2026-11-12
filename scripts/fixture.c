/* Tiny original, static smoke workload; no downloads or application image. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

static void fail(const char *what) { perror(what); exit(1); }
static void filename(char *out, size_t size, const char *name) {
    if (!*name || strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-_") != strlen(name)) exit(2);
    if (snprintf(out, size, "/workspace/%s", name) >= (int)size) exit(2);
}
static int read_file(const char *path) {
    char bytes[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0) fail("open");
    ssize_t n;
    while ((n = read(fd, bytes, sizeof(bytes))) > 0) if (write(1, bytes, (size_t)n) != n) fail("write");
    if (n < 0) fail("read");
    close(fd);
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "init")) {
        signal(SIGCHLD, SIG_IGN);
        /* Keep upper and immutable-lower descriptors AND mappings open over
           capture. The counter starts in memory, never from the filesystem. */
        int counter = open("/workspace/counter", O_CREAT | O_RDWR, 0666);
        int state = open("/workspace/mapped", O_CREAT | O_RDWR, 0666);
        int seed = open("/seed", O_RDONLY);
        if (counter < 0 || state < 0 || seed < 0 || ftruncate(state, 4096)) fail("init files");
        uint64_t *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, state, 0);
        const char *immutable = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, seed, 0);
        if (mapped == MAP_FAILED || immutable == MAP_FAILED) fail("mmap");
        volatile uint64_t count = 0;
        uint64_t nonce;
        if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) fail("getrandom");
        for (;;) {
            if (*immutable != 's') return 3;
            *mapped = ++count;
            mapped[1] = nonce;
            char line[64];
            int length = snprintf(line, sizeof(line), "%llu %llu\n", (unsigned long long)count, (unsigned long long)nonce);
            if (pwrite(counter, line, (size_t)length, 0) != length || ftruncate(counter, length)) fail("counter");
            usleep(100000);
        }
    }
    if (!strcmp(argv[1], "counter")) return read_file("/workspace/counter");
    if (!strcmp(argv[1], "read") && argc == 3) {
        char path[256]; filename(path, sizeof(path), argv[2]); return read_file(path);
    }
    if (!strcmp(argv[1], "write") && argc == 4) {
        char path[256]; filename(path, sizeof(path), argv[2]);
        int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
        if (fd < 0 || write(fd, argv[3], strlen(argv[3])) != (ssize_t)strlen(argv[3]) || close(fd)) fail("write fixture");
        return 0;
    }
    if (!strcmp(argv[1], "unlink") && argc == 3) {
        char path[256]; filename(path, sizeof(path), argv[2]);
        if (unlink(path)) fail("unlink");
        return 0;
    }
    if (!strcmp(argv[1], "isolation")) {
        if (getuid() != 65534 || getgid() != 65534 || getpid() == 1) return 4;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0 || errno != EPERM) return 5;
        if (!access("/sys", F_OK) || !access("/dev/nvidia0", F_OK)) return 6;
        return read_file("/proc/self/status");
    }
    if (!strcmp(argv[1], "orphan")) {
        pid_t child = fork();
        if (child < 0) fail("fork");
        if (!child) { close(0); close(1); close(2); for (;;) pause(); }
        return 0;
    }
    if (!strcmp(argv[1], "delay")) {
        struct timespec begin, end;
        if (clock_gettime(CLOCK_MONOTONIC, &begin)) fail("clock");
        usleep(1000000);
        if (clock_gettime(CLOCK_MONOTONIC, &end)) fail("clock");
        printf("%llu %llu\n", (unsigned long long)begin.tv_sec * 1000000000 + begin.tv_nsec,
               (unsigned long long)end.tv_sec * 1000000000 + end.tv_nsec);
        return 0;
    }
    if (!strcmp(argv[1], "hang")) { for (;;) pause(); }
    if (!strcmp(argv[1], "flood")) { char bytes[4096]; memset(bytes, 'x', sizeof(bytes)); for (;;) if (write(1, bytes, sizeof(bytes)) < 0) return 0; }
    return 2;
}
