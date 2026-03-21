/* CWE-78: OS Command Injection (environment variable pattern)
 * Uses unsanitized environment variable in shell command. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_backup(void) {
    const char *backup_dir = getenv("BACKUP_DIR");
    if (!backup_dir) backup_dir = "/tmp";
    char cmd[512];
    /* Environment variable injected into command */
    snprintf(cmd, sizeof(cmd), "tar czf %s/backup.tar.gz /data", backup_dir);
    system(cmd);
}

void send_notification(void) {
    const char *email = getenv("ADMIN_EMAIL");
    if (!email) return;
    char cmd[512];
    sprintf(cmd, "echo 'Backup done' | mail -s 'Status' %s", email);
    system(cmd);
}

int main(void) {
    run_backup();
    send_notification();
    return 0;
}
