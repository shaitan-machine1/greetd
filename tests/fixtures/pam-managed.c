#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

static const char *option(int argc, const char **argv, const char *key) {
    size_t length = strlen(key);
    for (int i = 0; i < argc; ++i) if (!strncmp(argv[i], key, length) && argv[i][length] == '=') return argv[i] + length + 1;
    return NULL;
}
static int trace(pam_handle_t *pamh, int argc, const char **argv, const char *event) {
    const char *path = option(argc, argv, "trace");
    const char *user = NULL;
    if (!path || pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_SESSION_ERR;
    FILE *file = fopen(path, "a"); if (!file) return PAM_SESSION_ERR;
    const char *seat = pam_getenv(pamh, "XDG_SEAT");
    int tasks = 0; DIR *directory = opendir("/proc/self/task");
    if (!directory) { fclose(file); return PAM_SESSION_ERR; }
    struct dirent *entry; while ((entry = readdir(directory))) if (entry->d_name[0] != '.') ++tasks;
    closedir(directory);
    const char *vt = pam_getenv(pamh, "XDG_VTNR");
    const void *tty = NULL; if (pam_get_item(pamh, PAM_TTY, &tty) != PAM_SUCCESS) {fclose(file); return PAM_SESSION_ERR;}
    fprintf(file, "%s %ld %ld %s %s %d %s %s\n", event, (long)getpid(), (long)geteuid(), user, seat ? seat : "-", tasks, vt ? vt : "-", tty && *(const char *)tty ? (const char *)tty : "-");
    fclose(file); return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    if (trace(pamh, argc, argv, "auth") != PAM_SUCCESS) return PAM_AUTH_ERR;
    char *response = NULL;
    int status = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "%s", "Fixture password:");
    if (status != PAM_SUCCESS) return status;
    int valid = response && !strcmp(response, "fixture-password");
    if (response) { memset(response, 0, strlen(response)); free(response); }
    if (!valid) return PAM_AUTH_ERR;
    const char *user = option(argc, argv, "user");
    return user ? pam_set_item(pamh, PAM_USER, user) : PAM_SYSTEM_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    const char *user = NULL, *parent = option(argc, argv, "runtime");
    if (!parent || pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_SESSION_ERR;
    struct passwd *account = getpwnam(user); if (!account) return PAM_SESSION_ERR;
    char path[4096], value[4128];
    if (snprintf(path, sizeof(path), "%s/%u", parent, account->pw_uid) >= (int)sizeof(path)) return PAM_SESSION_ERR;
    if (mkdir(path, 0700) && errno != EEXIST) return PAM_SESSION_ERR;
    if (chown(path, account->pw_uid, account->pw_gid)) return PAM_SESSION_ERR;
    snprintf(value, sizeof(value), "XDG_RUNTIME_DIR=%s", path);
    if (pam_putenv(pamh, value) != PAM_SUCCESS) return PAM_SESSION_ERR;
    return trace(pamh, argc, argv, "open");
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    if (trace(pamh, argc, argv, "close-enter") != PAM_SUCCESS) return PAM_SESSION_ERR;
    struct timespec delay = {.tv_sec = 2, .tv_nsec = 0};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
    int result = trace(pamh, argc, argv, "close");
    return option(argc, argv, "close_fail") ? PAM_SESSION_ERR : result;
}
