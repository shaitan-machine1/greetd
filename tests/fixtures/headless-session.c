/* Local validation shim only: real wlroots/libseat session, disposable SHM
 * output instead of DRM hardware. Never packaged or used in production. */
#define _GNU_SOURCE
#define WLR_USE_UNSTABLE
#include <wlr/backend.h>
#include <wlr/backend/session.h>
#include <wlr/backend/headless.h>
#include <libseat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void renderer(void) {
    setenv("WLR_RENDERER", "pixman", 1);
    setenv("WLR_RENDERER_ALLOW_SOFTWARE", "1", 1);
}
struct wlr_backend *wlr_backend_autocreate(struct wl_event_loop *loop, struct wlr_session **session) {
    const char *transport = getenv("SEATD_FD");
    const char *authority = getenv("MULTISEATD_AUTHORITY_FD");
    if (!!transport == !!authority) return NULL;
    struct stat inherited;
    if (fstat(atoi(transport ? transport : authority), &inherited) || !S_ISSOCK(inherited.st_mode)) return NULL;
    int native = authority != NULL;
    if (native && (!getenv("LIBSEAT_BACKEND") || strcmp(getenv("LIBSEAT_BACKEND"), "multiseatd"))) return NULL;
    *session = wlr_session_create(loop);
    if (!*session || getenv("SEATD_FD") || getenv("MULTISEATD_AUTHORITY_FD")) return NULL;
    int fd=libseat_get_fd((*session)->seat_handle);
    struct stat metadata;
    if (fd < 3 || fstat(fd,&metadata) || !S_ISSOCK(metadata.st_mode) || !(fcntl(fd,F_GETFD)&FD_CLOEXEC)) return NULL;
    if (!native && metadata.st_ino != inherited.st_ino) return NULL;
    char inode[64]; snprintf(inode, sizeof inode, "%llu", (unsigned long long)metadata.st_ino);
    setenv("GREETD_TEST_SEAT_INODE", inode, 1);
    if (native) {
        snprintf(inode,sizeof inode,"%llu",(unsigned long long)inherited.st_ino);
        setenv("GREETD_TEST_AUTHORITY_INODE",inode,1);
    }
    struct wlr_backend *backend = wlr_headless_backend_create(loop);
    if (!backend || !wlr_headless_add_output(backend, 800, 600)) return NULL;
    return backend;
}
