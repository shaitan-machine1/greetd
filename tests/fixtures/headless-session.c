/* Local validation shim only: real wlroots/libseat session, disposable SHM
 * output instead of DRM hardware. Never packaged or used in production. */
#define _GNU_SOURCE
#define WLR_USE_UNSTABLE
#include <wlr/backend.h>
#include <wlr/backend/session.h>
#include <wlr/backend/headless.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void renderer(void) {
    setenv("WLR_RENDERER", "pixman", 1);
    setenv("WLR_RENDERER_ALLOW_SOFTWARE", "1", 1);
}
struct wlr_backend *wlr_backend_autocreate(struct wl_event_loop *loop, struct wlr_session **session) {
    const char *value = getenv("SEATD_FD");
    if (!value || getenv("MULTISEATD_AUTHORITY_FD")) return NULL;
    struct stat metadata;
    if (fstat(atoi(value), &metadata)) return NULL;
    char inode[64]; snprintf(inode, sizeof inode, "%llu", (unsigned long long)metadata.st_ino);
    setenv("GREETD_TEST_SEAT_INODE", inode, 1);
    *session = wlr_session_create(loop);
    if (!*session || getenv("SEATD_FD")) return NULL;
    struct wlr_backend *backend = wlr_headless_backend_create(loop);
    if (!backend || !wlr_headless_add_output(backend, 800, 600)) return NULL;
    return backend;
}
