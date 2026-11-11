#define _GNU_SOURCE
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    if (argc < 3 || getenv("SEATD_FD") || getenv("MULTISEATD_AUTHORITY_FD")) return 1;
    const char *inode = getenv("GREETD_TEST_SEAT_INODE"); if (!inode) return 2;
    const char *authority = getenv("GREETD_TEST_AUTHORITY_INODE");
    DIR *directory = opendir("/proc/self/fd"); if (!directory) return 3;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        struct stat info;
        if (fstat(atoi(entry->d_name), &info)) return 4;
        if (S_ISSOCK(info.st_mode) && (info.st_ino == strtoull(inode, NULL, 10) || (authority && info.st_ino == strtoull(authority,NULL,10)))) return 5;
    }
    closedir(directory);
    errno = 0; if (open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC) >= 0 || errno != ENXIO) return 6;
    FILE *trace = fopen(argv[1], "a"); if (!trace) return 7;
    fprintf(trace, "%ld %s\n", (long)getpid(), inode); fclose(trace);
    unsetenv("GREETD_TEST_SEAT_INODE");
    unsetenv("GREETD_TEST_AUTHORITY_INODE");
    execv(argv[2], argv + 2); return 127;
}
