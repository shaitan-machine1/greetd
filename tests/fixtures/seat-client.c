#define _GNU_SOURCE
#include <libseat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <poll.h>
#include <time.h>
static void enable(struct libseat *seat, void *data) { (void)seat; *(int *)data = 1; }
static void disable(struct libseat *seat, void *data) { (void)data; libseat_disable_seat(seat); }
int main(int argc, char **argv) {
    if (argc != 4 || geteuid() == 0 || getenv("MULTISEATD_AUTHORITY_FD") || getenv("LD_PRELOAD")) return 1;
    const char *raw = getenv("SEATD_FD"), *name = getenv("XDG_SEAT"), *runtime = getenv("XDG_RUNTIME_DIR");
    if (!raw || !name || !runtime || getenv("XDG_VTNR") || strcmp(getenv("LOGNAME"), "nobody")) return 2;
    int fd = atoi(raw), count = 0;
    DIR *directory = opendir("/proc/self/fd"); if (!directory) return 3;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        int number = atoi(entry->d_name);
        if (number > 2 && number != dirfd(directory)) { if (number != fd) return 4; ++count; }
    }
    closedir(directory); if (count != 1) return 5;
    errno = 0; int tty = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty >= 0 || errno != ENXIO) return 6;
    struct stat metadata; if (stat(runtime, &metadata) || metadata.st_uid != geteuid() || (metadata.st_mode & 077)) return 7;
    int enabled = 0;
    struct libseat_seat_listener listener = { .enable_seat = enable, .disable_seat = disable };
    struct libseat *seat = libseat_open_seat(&listener, &enabled);
    if (!seat || getenv("SEATD_FD") || strcmp(libseat_seat_name(seat), name)) return 8;
    while (!enabled) if (libseat_dispatch(seat, 2000) < 0) return 9;
    if (fcntl(fd, F_GETFD) < 0 || !(fcntl(fd, F_GETFD) & FD_CLOEXEC)) return 10;
    FILE *trace = fopen(argv[2], "a"); if (!trace) return 11;
    int access = open(argv[3], O_RDONLY | O_CLOEXEC); if (access < 0) return 12; close(access);
    fprintf(trace, "%s %ld %ld %ld %u %s %s\n", argv[1], (long)getpid(), (long)getppid(), (long)getsid(0), geteuid(), name, runtime); fclose(trace);
    if (!strcmp(argv[1], "user")) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 200000000}; nanosleep(&delay, NULL);
    } else {
        for (;;) { if (libseat_dispatch(seat, 100) < 0) break; }
    }
    libseat_close_seat(seat); return 0;
}
