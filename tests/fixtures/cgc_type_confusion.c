/*
 * CGC-style challenge: Type confusion vulnerability
 * CWE-843: Access of Resource Using Incompatible Type
 *
 * A message dispatcher uses a type tag to select a handler, but fails
 * to validate the tag before casting the payload pointer.  An attacker
 * can supply a mismatched tag to reinterpret the object.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum msg_type { MSG_TEXT = 1, MSG_ADMIN = 2 };

struct text_msg {
    int  type;
    char body[64];
};

struct admin_msg {
    int  type;
    void (*handler)(void);
    int  auth_token;
};

static void admin_action(void) {
    printf("ADMIN: system reset executed\n");
}

static void dispatch(void *msg) {
    int type = *(int *)msg;

    /* VULN: attacker controls the type field; a text_msg whose first
       bytes of body overlap with the handler function pointer in
       admin_msg will be called as a function pointer */
    if (type == MSG_ADMIN) {
        struct admin_msg *am = (struct admin_msg *)msg;
        if (am->handler)
            am->handler();
    } else {
        struct text_msg *tm = (struct text_msg *)msg;
        printf("TEXT: %s\n", tm->body);
    }
}

int main(void) {
    struct text_msg m;
    memset(&m, 0, sizeof(m));

    printf("Enter type (1=text, 2=admin): ");
    scanf("%d", &m.type);

    printf("Enter message body: ");
    getchar();
    fgets(m.body, sizeof(m.body), stdin);

    /* If attacker enters type=2, the body bytes are interpreted as
       an admin_msg, causing a controlled function pointer call */
    dispatch(&m);
    return 0;
}
