#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Only loaded inside the harness's private mount namespace. No host PAM edits. */
static void record(pam_handle_t *pamh, const char *stage) {
    const char *path = getenv("GREETD_TEST_LOG");
    if (!path) return;
    const void *user = NULL, *tty = NULL;
    pam_get_item(pamh, PAM_USER, &user);
    pam_get_item(pamh, PAM_TTY, &tty);
    const char *seat = pam_getenv(pamh, "XDG_SEAT");
    const char *vt = pam_getenv(pamh, "XDG_VTNR");
    FILE *file = fopen(path, "ae");
    if (file) {
        fprintf(file, "%s\t%s\t%s\t%s\t%s\n", stage,
                user ? (const char *)user : "", tty ? (const char *)tty : "",
                seat ? seat : "", vt ? vt : "");
        fclose(file);
    }
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p, int f, int n, const char **a) {
    (void)f; (void)n; (void)a;
    record(p, "auth");
    return getenv("GREETD_TEST_FAIL_AUTH") ? PAM_AUTH_ERR : PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int f, int n, const char **a) {
    (void)f; (void)n; (void)a; record(p, "account"); return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int f, int n, const char **a) {
    (void)n; (void)a; record(p, (f & PAM_DELETE_CRED) ? "delete" : "establish");
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int f, int n, const char **a) {
    (void)f; (void)n; (void)a;
    record(p, "open");
    const char *user = getenv("GREETD_TEST_FINAL_USER");
    if (user && pam_set_item(p, PAM_USER, user) != PAM_SUCCESS) return PAM_SESSION_ERR;
    const char *bus = getenv("DBUS_SYSTEM_BUS_ADDRESS");
    char *value = NULL;
    if (bus && asprintf(&value, "DBUS_SYSTEM_BUS_ADDRESS=%s", bus) >= 0) {
        pam_putenv(p, value); free(value);
    }
    return getenv("GREETD_TEST_FAIL_OPEN") ? PAM_SESSION_ERR : PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int f, int n, const char **a) {
    (void)f; (void)n; (void)a;
    record(p, "close");
    const char *gate = getenv("GREETD_TEST_CLOSE_GATE");
    for (unsigned i = 0; gate && access(gate, F_OK) != 0 && i < 500; ++i) usleep(10000);
    record(p, "closed");
    return getenv("GREETD_TEST_FAIL_CLOSE") ? PAM_SESSION_ERR : PAM_SUCCESS;
}
