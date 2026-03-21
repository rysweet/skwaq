/* CWE-190: Integer Overflow or Wraparound (allocation size pattern)
 * Integer overflow in size calculation leads to small allocation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *safe_calloc(unsigned int nmemb, unsigned int size) {
    /* No overflow check on multiplication */
    unsigned int total = nmemb * size;
    void *p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

int process_image(unsigned int width, unsigned int height, unsigned int bpp) {
    /* width * height * bpp can overflow */
    unsigned int size = width * height * bpp;
    unsigned char *pixels = (unsigned char *)malloc(size);
    if (!pixels) return -1;
    /* Write beyond allocated size if overflow occurred */
    for (unsigned int i = 0; i < width * height * bpp && i < 1024; i++)
        pixels[i] = 0xFF;
    free(pixels);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) return 1;
    unsigned int w = (unsigned int)atoi(argv[1]);
    unsigned int h = (unsigned int)atoi(argv[2]);
    unsigned int bpp = (unsigned int)atoi(argv[3]);
    return process_image(w, h, bpp);
}
