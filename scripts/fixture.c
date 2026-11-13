/* Tiny original, static smoke workload; no downloads or application image. */
#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>

/* Print the current system error with context and exit unsuccessfully. */
static void fail(const char *what) { perror(what); exit(1); }
/* Validate a simple workspace filename and build its full path, exiting if invalid or too long. */
static void filename(char *out, size_t size, const char *name) {
    if (!*name || strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-_") != strlen(name)) exit(2);
    if (snprintf(out, size, "/workspace/%s", name) >= (int)size) exit(2);
}
/* Copy a file to standard output in small chunks, failing on read or write errors. */
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
/* Open a connected loopback TCP pair on port 9000 (listener, client and accepted end), each with a */
/* one-second receive timeout. The pair stays ESTABLISHED for the init's lifetime. */
static void loopback_pair(int *client, int *server) {
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(9000), .sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    struct timeval timeout = {.tv_sec=1};
    int one = 1, listener = socket(AF_INET, SOCK_STREAM, 0);
    *client = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || *client < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))
        || bind(listener, (struct sockaddr *)&a, sizeof(a)) || listen(listener, 1)
        || connect(*client, (struct sockaddr *)&a, sizeof(a)) || (*server = accept(listener, NULL, NULL)) < 0) fail("loopback pair");
    close(listener);
    if (setsockopt(*client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
        || setsockopt(*server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) fail("loopback timeout");
}
/* Check denied calls, argument restrictions and fallback errors without changing guest state. */
/* unshare(0) and invalid keyctl distinguish filtering from a capability-only refusal. */
static int syscall_policy(void) {
    if (syscall(__NR_unshare, 0) != -1 || errno != EPERM) return 5;
    if (syscall(__NR_keyctl, -1, 0, 0, 0, 0) != -1 || errno != EPERM) return 5;
    if (syscall(__NR_userfaultfd, O_CLOEXEC | 1 /* UFFD_USER_MODE_ONLY */) != -1 || errno != EPERM) return 5;
    if (syscall(__NR_io_uring_setup, 1, NULL) != -1 || errno != ENOSYS) return 5;
    if (syscall(__NR_io_uring_enter, -1, 0, 0, 0, NULL, 0) != -1 || errno != ENOSYS) return 5;
    if (syscall(__NR_io_uring_register, -1, 0, NULL, 0) != -1 || errno != ENOSYS) return 5;
    if (syscall(__NR_clone3, NULL, 0) != -1 || errno != ENOSYS) return 5;
    if (syscall(0x3fffffff, 0, 0, 0, 0, 0, 0) != -1 || errno != ENOSYS) return 5;
    if (socket(AF_INET, SOCK_STREAM, 262 /* IPPROTO_MPTCP */) >= 0 || errno != EPROTONOSUPPORT) return 5;
    if (socket(AF_VSOCK, SOCK_STREAM, 0) >= 0 || errno != EPERM) return 5;
    printf("seccomp_policy unshare=EPERM keyctl=EPERM userfaultfd=EPERM io_uring=ENOSYS clone3=ENOSYS unknown=ENOSYS mptcp=EPROTONOSUPPORT vsock=EPERM\n");
    return 0;
}
/* Dispatch persistent counter/TCP/HTTP services, file/isolation/policy checks and command bounds. */
/* Monitor modes exit immediately, wait for a trigger then exit, or exceed the sandbox memory cap. */
/* Init rechecks syscall policy each tick, including after restore, and exits on any mismatch. */
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "seccomp")) return syscall_policy();
    if (!strcmp(argv[1], "exit-now")) return 23;
    if (!strcmp(argv[1], "monitor-exit") || !strcmp(argv[1], "monitor-oom")) {
        while (access("/workspace/go", F_OK) != 0) usleep(10000);
        if (!strcmp(argv[1], "monitor-exit")) return 37;
        /* The gate caps this container at 64 MiB; touch real pages rather than just reserving them. */
        for (int i = 0; i < 128; i++) {
            volatile char *memory = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (memory == MAP_FAILED) fail("oom allocation");
            for (int offset = 0; offset < (1 << 20); offset += 4096) memory[offset] = 1;
        }
        return 99;
    }
    if (!strcmp(argv[1], "process-group")) {
        pid_t group = getpgrp();
        if (group < 0) fail("getpgrp");
        printf("%ld\n", (long)group);
        return 0;
    }
    if (!strcmp(argv[1], "connect") && argc == 5) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) fail("tcp socket");
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons((uint16_t)atoi(argv[3]))};
        if (inet_pton(AF_INET, argv[2], &a.sin_addr) != 1) return 2;
        int ok = connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0;
        if (!ok && errno == EINPROGRESS) {
            struct pollfd p = {.fd=fd, .events=POLLOUT};
            if (poll(&p, 1, atoi(argv[4]) ? 1500 : 350) > 0) { int error=0; socklen_t n=sizeof(error); ok = !getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) && !error; }
        }
        close(fd);
        printf("connected=%d\n", ok);
        return ok == atoi(argv[4]) ? 0 : 7;
    }
    if (!strcmp(argv[1], "transfer") && argc == 3) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        int discover = IP_PMTUDISC_DO;
        struct timeval timeout = {.tv_sec=3};
        if (fd < 0 || setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discover, sizeof(discover))
            || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
            || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) fail("transfer socket");
        struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(18080)};
        if (inet_pton(AF_INET, argv[2], &a.sin_addr) != 1 || connect(fd, (struct sockaddr *)&a, sizeof(a))) fail("transfer connect");
        int before=0, after=0; socklen_t size=sizeof(before);
        if (getsockopt(fd, IPPROTO_IP, IP_MTU, &before, &size)) fail("initial mtu");
        unsigned char payload[65536];
        for (size_t i=0; i<sizeof(payload); i++) payload[i]=(unsigned char)(i%251);
        for (size_t sent=0; sent<sizeof(payload);) {
            ssize_t n=send(fd, payload+sent, sizeof(payload)-sent, MSG_NOSIGNAL);
            if (n <= 0) fail("transfer send");
            sent+=(size_t)n;
        }
        char response[8]; size_t received=0;
        while (received<sizeof(response)) {
            ssize_t n=recv(fd, response+received, sizeof(response)-received, 0);
            if (n <= 0) fail("transfer acknowledgement");
            received+=(size_t)n;
        }
        if (memcmp(response, "OK65536\n", sizeof(response))) return 8;
        if (getsockopt(fd, IPPROTO_IP, IP_MTU, &after, &size)) fail("discovered mtu");
        close(fd);
        printf("bytes=65536 mtu_before=%d mtu_after=%d\n", before, after);
        return after == 1280 ? 0 : 9;
    }
    if (!strcmp(argv[1], "init") || !strcmp(argv[1], "init-network")) {
        int listener = -1;
        if (!strcmp(argv[1], "init-network")) {
            listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(8080), .sin_addr={.s_addr=INADDR_ANY}};
            int one=1;
            if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) || bind(listener, (struct sockaddr *)&a, sizeof(a)) || listen(listener, 16)) fail("listen");
        }
        /* No SIGCHLD handling: reaping orphans is the job of the PID 1 init.
           Keep upper and immutable-lower descriptors AND mappings open over
           capture. The counter starts in memory, never from the filesystem. */
        int counter = open("/workspace/counter", O_CREAT | O_RDWR, 0666);
        int loopback = open("/workspace/loopback", O_CREAT | O_RDWR, 0666);
        int client = -1, server = -1, loopback_error = 0;
        uint64_t roundtrips = 0;
        if (loopback < 0) fail("loopback file");
        loopback_pair(&client, &server);
        int state = open("/workspace/mapped", O_CREAT | O_RDWR, 0666);
        int seed = open("/seed", O_RDONLY);
        if (counter < 0 || state < 0 || seed < 0 || ftruncate(state, 4096)) fail("init files");
        uint64_t *mapped = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, state, 0);
        const char *immutable = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, seed, 0);
        if (mapped == MAP_FAILED || immutable == MAP_FAILED) fail("mmap");
        volatile uint64_t count = 0;
        uint64_t nonce;
        if (getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) fail("getrandom");
        int held = -1;
        for (;;) {
            if (syscall_policy()) return 5;
            if (listener >= 0 && held < 0 && !access("/workspace/hold-external", F_OK)) {
                held = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(18080)};
                if (inet_pton(AF_INET, "198.18.0.1", &a.sin_addr) != 1 || connect(held, (struct sockaddr *)&a, sizeof(a))) fail("held connect");
                int ready = open("/workspace/holding", O_CREAT | O_WRONLY, 0666);
                if (ready < 0 || write(ready, "ready", 5) != 5 || close(ready)) fail("held ready");
            }
            if (*immutable != 's') return 3;
            /* One byte each way over the same ESTABLISHED connection on every tick;
               a restore that broke it records the error instead of reconnecting. */
            if (!loopback_error) {
                char ping = 'p', pong = 0;
                if (send(client, &ping, 1, MSG_NOSIGNAL) != 1 || recv(server, &ping, 1, 0) != 1
                    || send(server, "q", 1, MSG_NOSIGNAL) != 1 || recv(client, &pong, 1, 0) != 1 || pong != 'q') loopback_error = errno ? errno : -1;
                else roundtrips++;
                char status[64];
                int size = snprintf(status, sizeof(status), "roundtrips=%llu error=%d\n", (unsigned long long)roundtrips, loopback_error);
                if (pwrite(loopback, status, (size_t)size, 0) != size || ftruncate(loopback, size)) fail("loopback status");
            }
            *mapped = ++count;
            mapped[1] = nonce;
            char line[64];
            int length = snprintf(line, sizeof(line), "%llu %llu\n", (unsigned long long)count, (unsigned long long)nonce);
            if (pwrite(counter, line, (size_t)length, 0) != length || ftruncate(counter, length)) fail("counter");
            /* Wait out the 100 ms tick, answering each HTTP client as soon as it connects. */
            struct timespec tick;
            if (clock_gettime(CLOCK_MONOTONIC, &tick)) fail("tick clock");
            for (;;) {
                struct timespec now;
                if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("tick clock");
                long left = 100 - ((now.tv_sec-tick.tv_sec)*1000 + (now.tv_nsec-tick.tv_nsec)/1000000);
                if (left <= 0) break;
                if (listener < 0) { usleep((useconds_t)left*1000); break; }
                struct pollfd incoming = {.fd=listener, .events=POLLIN};
                if (poll(&incoming, 1, (int)left) <= 0) continue;
                int client = accept4(listener, NULL, NULL, SOCK_NONBLOCK);
                if (client >= 0) {
                    struct pollfd p = {.fd=client, .events=POLLIN};
                    char request[32768] = {0};
                    size_t received = 0, body_length = 0;
                    char *headers_end = NULL;
                    while (received < sizeof(request)-1 && poll(&p, 1, 500) > 0) {
                        ssize_t count = read(client, request+received, sizeof(request)-1-received);
                        if (count <= 0) break;
                        received += (size_t)count;
                        headers_end = strstr(request, "\r\n\r\n");
                        if (headers_end) {
                            char *length = strcasestr(request, "\r\ncontent-length:");
                            body_length = length ? strtoul(length+17, NULL, 10) : 0;
                            /* Larger bodies (/count) are read by their handler. */
                            if (body_length > 16384 || received >= (size_t)(headers_end+4-request)+body_length) break;
                        }
                    }
                    if (received && headers_end) {
                        if (strstr(request, " /slow ")) usleep(500000);
                        unsigned long bytes = 0, value = 0, delay = 0;
                        char *route = strchr(request, ' ');
                        if (route && sscanf(route, " /delay/%lu", &delay) == 1 && delay <= 31000) usleep((useconds_t)(delay*1000));
                        unsigned long chunks = 0, gap = 0;
                        if (route && sscanf(route, " /pattern/%lu", &bytes) == 1 && bytes <= 67108864) {
                            /* Binary body: byte i is i % 251, sent with Content-Length. */
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n", bytes);
                            unsigned char chunk[4096];
                            for (size_t sent = 0; sent < bytes;) {
                                size_t left = bytes-sent, size = left < sizeof(chunk) ? left : sizeof(chunk);
                                for (size_t i = 0; i < size; i++) chunk[i] = (unsigned char)((sent+i) % 251);
                                for (size_t done = 0; done < size;) {
                                    struct pollfd writable = {.fd=client, .events=POLLOUT};
                                    ssize_t count = send(client, chunk+done, size-done, MSG_NOSIGNAL);
                                    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) && poll(&writable, 1, 2000) > 0) continue;
                                    if (count <= 0) { sent = bytes; break; }
                                    done += (size_t)count;
                                }
                                sent += size;
                            }
                        } else if (route && sscanf(route, " /chunked/%lu/%lu", &chunks, &gap) == 2 && chunks <= 100 && gap <= 1000) {
                            /* Chunked transfer coding: "part-i" chunks with a gap between them. */
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
                            for (unsigned long i = 0; i < chunks; i++) {
                                char part[32]; int size = snprintf(part, sizeof(part), "part-%lu\n", i);
                                if (dprintf(client, "%x\r\n%s\r\n", size, part) < 0) break;
                                usleep((useconds_t)(gap*1000));
                            }
                            dprintf(client, "0\r\n\r\n");
                        } else if (route && !strncmp(route, " /count ", 8)) {
                            /* Read a Content-Length body of up to 64 MiB in pieces; answer its size and FNV-1a hash. */
                            size_t have = received-(size_t)(headers_end+4-request), total = 0;
                            uint64_t hash = 1469598103934665603ULL;
                            unsigned char piece[16384];
                            const unsigned char *data = (const unsigned char *)headers_end+4;
                            while (body_length <= 67108864) {
                                for (size_t i = 0; i < have && total < body_length; i++, total++) hash = (hash ^ data[i]) * 1099511628211ULL;
                                if (total >= body_length) break;
                                struct pollfd readable = {.fd=client, .events=POLLIN};
                                if (poll(&readable, 1, 2000) <= 0) break;
                                ssize_t count = read(client, piece, sizeof(piece));
                                if (count <= 0) break;
                                data = piece; have = (size_t)count;
                            }
                            char body[96]; int length = snprintf(body, sizeof(body), "bytes=%zu fnv=%016llx", total, (unsigned long long)hash);
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", length, body);
                        } else if (route && sscanf(route, " /sized/%lu/%lu", &bytes, &value) == 2 && bytes <= 8388609 && value <= 127) {
                            char chunk[4096]; memset(chunk, (int)value, sizeof(chunk));
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n", bytes);
                            struct timespec transmit_start;
                            if (clock_gettime(CLOCK_MONOTONIC, &transmit_start)) fail("transmit clock");
                            for (size_t sent = 0; sent < bytes;) {
                                size_t left = bytes-sent;
                                ssize_t count = send(client, chunk, left < sizeof(chunk) ? left : sizeof(chunk), MSG_NOSIGNAL);
                                if (count < 0 && errno == EINTR) continue;
                                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                                    struct timespec now;
                                    if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("transmit clock");
                                    struct pollfd writable = {.fd=client, .events=POLLOUT};
                                    if (now.tv_sec-transmit_start.tv_sec < 10 && poll(&writable, 1, 100) >= 0) continue;
                                }
                                if (count <= 0) break;
                                sent += (size_t)count;
                            }
                        } else if (strstr(request, " /body-size ")) {
                            size_t actual = received-(size_t)(headers_end+4-request);
                            char body[64]; int length = snprintf(body, sizeof(body), "body_bytes=%zu", actual);
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", length, body);
                        } else if (strstr(request, " /large ")) {
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: 70000\r\nConnection: close\r\n\r\n");
                        } else if (strstr(request, " /binary ")) {
                            dprintf(client, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n");
                            (void)send(client, "\xff", 1, MSG_NOSIGNAL);
                        } else if (strstr(request, " /headers-large ")) {
                            char header[20000]; memset(header, 'a', sizeof(header));
                            dprintf(client, "HTTP/1.1 200 OK\r\nX-Large: ");
                            (void)send(client, header, sizeof(header), MSG_NOSIGNAL);
                            dprintf(client, "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        } else if (strstr(request, " /redirect ")) {
                            dprintf(client, "HTTP/1.1 302 Found\r\nLocation: http://198.18.0.2:18080/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        } else {
                            char response[sizeof(request)+512];
                            int length = snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(request), request);
                            if (length > 0 && (size_t)length < sizeof(response)) (void)send(client, response, (size_t)length, MSG_NOSIGNAL);
                        }
                    }
                    close(client);
                }
            }
        }
    }
    if (!strcmp(argv[1], "counter")) return read_file("/workspace/counter");
    if (!strcmp(argv[1], "loopback")) {
        /* The init's status line, then the ESTABLISHED (state 01) sockets on port 9000 (0x2328). */
        char line[512]; unsigned local = 0, remote = 0, state = 0; int established = 0;
        FILE *tcp = fopen("/proc/net/tcp", "r");
        if (!tcp) fail("tcp table");
        while (fgets(line, sizeof(line), tcp))
            if (sscanf(line, " %*d: %*8x:%x %*8x:%x %x", &local, &remote, &state) == 3 && state == 1 && (local == 9000 || remote == 9000)) established++;
        fclose(tcp);
        read_file("/workspace/loopback");
        printf("established=%d\n", established);
        return 0;
    }
    if (!strcmp(argv[1], "init-name")) {
        /* argv[0] of PID 1 in this sandbox's PID namespace. */
        char name[256] = {0};
        int fd = open("/proc/1/cmdline", O_RDONLY);
        if (fd < 0 || read(fd, name, sizeof(name) - 1) < 0) fail("pid 1 cmdline");
        printf("%s\n", name);
        return 0;
    }
    if (!strcmp(argv[1], "orphan-exit")) {
        /* The child outlives this command and is reparented to PID 1, which must reap it. */
        pid_t child = fork();
        if (child < 0) fail("fork");
        if (!child) { usleep(100000); _exit(0); }
        return 0;
    }
    if (!strcmp(argv[1], "zombies")) {
        /* Count zombie (state Z) processes visible in this PID namespace. */
        int zombies = 0; struct dirent *entry; DIR *proc = opendir("/proc");
        if (!proc) fail("proc");
        while ((entry = readdir(proc))) {
            char path[300], stat[512] = {0};
            if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
            snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            ssize_t n = read(fd, stat, sizeof(stat) - 1);
            close(fd);
            char *end = n > 0 ? strrchr(stat, ')') : NULL;
            if (end && end[1] == ' ' && end[2] == 'Z') zombies++;
        }
        closedir(proc);
        printf("%d\n", zombies);
        return 0;
    }
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
    if (!strcmp(argv[1], "isolation") || !strcmp(argv[1], "network-isolation")) {
        if (getuid() != 65534 || getgid() != 65534 || getpid() == 1) return 4;
        if (syscall_policy()) return 5;
        /* Raw packet sockets need a capability the workload does not have. */
        if (socket(AF_PACKET, SOCK_RAW, 0) >= 0 || errno != EPERM) return 5;
        /* Isolated: loopback only. Both modes: IPv6 has no route. */
        struct sockaddr_in v4 = {.sin_family=AF_INET, .sin_port=htons(80)};
        struct sockaddr_in6 v6 = {.sin6_family=AF_INET6, .sin6_port=htons(80)};
        if (inet_pton(AF_INET, "198.51.100.1", &v4.sin_addr) != 1 || inet_pton(AF_INET6, "2001:db8::1", &v6.sin6_addr) != 1) return 2;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) fail("tcp socket");
        if (strcmp(argv[1], "network-isolation") && (connect(fd, (struct sockaddr *)&v4, sizeof(v4)) == 0 || errno != ENETUNREACH)) return 5;
        close(fd);
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) fail("tcp6 socket");
        if (connect(fd, (struct sockaddr *)&v6, sizeof(v6)) == 0 || (errno != ENETUNREACH && errno != EADDRNOTAVAIL)) return 5;
        close(fd);
        fflush(stdout);
        if (!access("/sys", F_OK) || !access("/dev/nvidia0", F_OK)) return 6;
        return read_file("/proc/self/status");
    }
    if (!strcmp(argv[1], "orphan")) {
        pid_t child = fork();
        if (child < 0) fail("fork");
        if (!child) { close(0); close(1); close(2); for (;;) pause(); }
        return 0;
    }
    if (!strcmp(argv[1], "ticks")) {
        /* Five lines, 200 ms apart, each flushed at once (streamed exec output). */
        for (int i = 0; i < 5; i++) { printf("tick %d\n", i); fflush(stdout); usleep(200000); }
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
    if (!strcmp(argv[1], "dual-output")) {
        char out[4096], err[4096]; memset(out, 'o', sizeof(out)); memset(err, 'e', sizeof(err));
        for (int i=0; i<32; i++) if (write(1, out, sizeof(out)) != sizeof(out) || write(2, err, sizeof(err)) != sizeof(err)) return 1;
        return 0;
    }
    if (!strcmp(argv[1], "flood-both")) {
        char bytes[4096]; memset(bytes, 'x', sizeof(bytes));
        for (;;) if (write(1, bytes, sizeof(bytes)) < 0 || write(2, bytes, sizeof(bytes)) < 0) return 0;
    }
    if (!strcmp(argv[1], "hang")) { for (;;) pause(); }
    if (!strcmp(argv[1], "flood")) { char bytes[4096]; memset(bytes, 'x', sizeof(bytes)); for (;;) if (write(1, bytes, sizeof(bytes)) < 0) return 0; }
    return 2;
}
