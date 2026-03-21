/*
 * CGC-style challenge: Array index out of bounds
 * CWE-129: Improper Validation of Array Index
 *
 * A scoreboard service lets players set their score by index.
 * The index is read from user input but only partially validated,
 * allowing out-of-bounds write to corrupt adjacent data.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_PLAYERS 8

struct scoreboard {
    int  scores[NUM_PLAYERS];
    int  admin_flag;
    char winner_name[32];
};

static void set_score(struct scoreboard *sb) {
    int idx, value;

    printf("Player index: ");
    scanf("%d", &idx);
    printf("Score: ");
    scanf("%d", &value);

    /* VULN: only checks upper bound, negative indices are allowed,
       and the upper bound check is > instead of >= allowing index 8
       to write into admin_flag */
    if (idx > NUM_PLAYERS) {
        printf("Invalid index\n");
        return;
    }

    sb->scores[idx] = value;
    printf("Player %d score set to %d\n", idx, value);
}

static void show_winner(struct scoreboard *sb) {
    if (sb->admin_flag) {
        printf("ADMIN MODE: winner is %s\n", sb->winner_name);
    } else {
        int best = 0;
        for (int i = 1; i < NUM_PLAYERS; i++)
            if (sb->scores[i] > sb->scores[best])
                best = i;
        printf("Winner: player %d with score %d\n", best, sb->scores[best]);
    }
}

int main(void) {
    struct scoreboard sb;
    memset(&sb, 0, sizeof(sb));

    set_score(&sb);
    show_winner(&sb);
    return 0;
}
