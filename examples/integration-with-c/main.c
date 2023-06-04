#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bof.h"

int main(int argc, char *argv[]) {
    ssize_t ret;
    ssize_t len;
    int fd;
    struct stat sb;
    const char *filename;

    if (argc < 2) {
        printf("Usage: %s <bof-filename>\n", argv[0]);
        return 0;
    }
    filename = argv[1];
    printf("filename: %s\n", filename);

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        printf("File not found. Please run 'zig build' in the root of the project.\n");
        return 1;
    }

    if (fstat(fd, &sb) == -1) {
        printf("fstat failed.\n");
        return 2;
    }
    len = sb.st_size;
    printf("bof len (fstat): %ld\n", sb.st_size);

    char* buf = (char *)malloc(sizeof(char)*len);
    if (buf == NULL) return 3;
    char* p = buf;

    printf("Running bof from command line C application ...\n");

    while (len != 0 && (ret = read(fd, p, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            printf("'read' failed.\n");
            break;
        }
        len -= ret;
        p += ret;
    }

    int bof_result = bofLoadAndRun("bof", (unsigned char*)buf, ret, NULL, 0, NULL);

    return 0;
}
