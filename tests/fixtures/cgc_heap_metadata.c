/*
 * CGC-style challenge: Heap metadata corruption via overflow
 * CWE-122: Heap-based Buffer Overflow
 *
 * A note-taking service allocates heap buffers for notes.  An edit
 * operation writes beyond the allocated size, corrupting adjacent
 * heap metadata or the next chunk's data.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOTE_SIZE 64
#define MAX_NOTES 4

static char *notes[MAX_NOTES];

static void create_note(int idx, const char *text) {
    if (idx < 0 || idx >= MAX_NOTES) return;
    notes[idx] = malloc(NOTE_SIZE);
    if (notes[idx])
        strncpy(notes[idx], text, NOTE_SIZE - 1);
}

static void edit_note(int idx) {
    char buf[256];
    if (idx < 0 || idx >= MAX_NOTES || !notes[idx]) return;

    printf("New content: ");
    if (fgets(buf, sizeof(buf), stdin) == NULL) return;

    /* VULN: copies up to 256 bytes into a 64-byte heap allocation,
       overwriting the next heap chunk's metadata */
    strcpy(notes[idx], buf);
}

static void delete_note(int idx) {
    if (idx < 0 || idx >= MAX_NOTES) return;
    free(notes[idx]);
    notes[idx] = NULL;
}

int main(void) {
    create_note(0, "first note");
    create_note(1, "second note");

    /* Attacker edits note 0 with oversized payload */
    edit_note(0);

    /* Freeing note 1 after its metadata has been corrupted */
    delete_note(1);
    delete_note(0);
    return 0;
}
