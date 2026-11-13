#define _GNU_SOURCE
#include <libseat.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void enable(struct libseat *seat, void *data) { (void)seat; (void)data; }
static void disable(struct libseat *seat, void *data) {
    (void)data; assert(libseat_disable_seat(seat) == 0);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *authority = getenv("MULTISEATD_AUTHORITY_FD");
    assert(authority);
    int fd = atoi(authority);
    struct libseat_seat_listener listener = { .enable_seat = enable, .disable_seat = disable };
    struct libseat *seat = libseat_open_seat(&listener, NULL);
    assert(seat);
    assert(!getenv("MULTISEATD_AUTHORITY_FD"));
    /* The descriptor number can be reused by the broker connection. */
    assert(fcntl(fd, F_GETFD) < 0 || (fcntl(fd, F_GETFD) & FD_CLOEXEC));
    assert(fcntl(libseat_get_fd(seat), F_GETFD) & FD_CLOEXEC);
    FILE *report = fopen(argv[1], "we");
    assert(report);
    fprintf(report, "native authority consumed, seat=%s\n", libseat_seat_name(seat));
    fclose(report);
    assert(libseat_close_seat(seat) == 0);
    return 0;
}
