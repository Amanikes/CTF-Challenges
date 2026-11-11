/*
 * Northstar License Manager 2.4.1
 *
 * Legacy licensing utility recovered from a retired Northstar Systems
 * deployment. The tool reads the encoded license stored in license.dat and
 * validates a key typed by the operator.
 *
 * The accepted key is never stored in this executable. Only the transformation
 * key and the encoded data file are available locally.
 */

#define _POSIX_C_SOURCE 200809L

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "northstar_xor.h"

#define LICENSE_FILE "license.dat"
#define APP_NAME "Northstar License Manager"
#define APP_VERSION "2.4.1"

/*
 * Transform the candidate key with the repeating XOR key and compare the
 * result against the encoded license. The difference accumulator avoids an
 * early exit, but the loop is otherwise a plain byte-by-byte comparison.
 */
__attribute__((noinline, used)) static int validate_license(const char *candidate,
                                                            size_t candidate_len,
                                                            const unsigned char *encoded,
                                                            size_t encoded_len)
{
    if (candidate_len != encoded_len)
        return 0;

    unsigned int difference = 0;

    for (size_t i = 0; i < candidate_len; ++i)
    {
        unsigned char transformed =
            (unsigned char)((unsigned char)candidate[i] ^ NORTHSTAR_XOR_KEY[i % NORTHSTAR_XOR_KEY_LEN]);
        difference |= (unsigned int)(transformed ^ encoded[i]);
    }

    return difference == 0;
}

static int executable_directory(char *out, size_t capacity)
{
    char link[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", link, sizeof link - 1);

    if (length <= 0)
        return -1;

    link[length] = '\0';

    char *separator = strrchr(link, '/');
    if (separator == NULL)
        return -1;

    *separator = '\0';

    if (strlen(link) >= capacity)
        return -1;

    strcpy(out, link);
    return 0;
}

/* Returns 0 on success, 1 when the file is absent, 2 when its content is invalid. */
static int load_license(const char *path, unsigned char *buffer, size_t capacity, size_t *length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return 1;

    size_t read = fread(buffer, 1, capacity, file);
    int trailing = fgetc(file);
    int failed = ferror(file);

    fclose(file);

    if (failed != 0 || trailing != EOF || read == 0)
        return 2;

    *length = read;
    return 0;
}

int main(void)
{
    char directory[PATH_MAX];
    char data_path[PATH_MAX];

    if (executable_directory(directory, sizeof directory) != 0)
    {
        fprintf(stderr, "%s: unable to resolve the executable path\n", APP_NAME);
        return 2;
    }

    if (snprintf(data_path, sizeof data_path, "%s/%s", directory, LICENSE_FILE) >= (int)sizeof data_path)
    {
        fprintf(stderr, "%s: license data path is too long\n", APP_NAME);
        return 2;
    }

    unsigned char encoded[NORTHSTAR_MAX_LICENSE];
    size_t encoded_len = 0;
    int status = load_license(data_path, encoded, sizeof encoded, &encoded_len);

    if (status == 1)
    {
        fprintf(stderr, "%s: %s is missing; keep it next to the executable\n", APP_NAME, LICENSE_FILE);
        return 2;
    }

    if (status != 0)
    {
        fprintf(stderr, "%s: %s could not be read or is corrupted\n", APP_NAME, LICENSE_FILE);
        return 2;
    }

    printf("%s %s\n", APP_NAME, APP_VERSION);
    printf("Licensed to: Northstar Systems (legacy entitlement)\n");
    printf("Enter license key: ");
    fflush(stdout);

    char line[NORTHSTAR_MAX_LICENSE + 4];
    if (fgets(line, (int)sizeof line, stdin) == NULL)
    {
        printf("\nNo license key entered.\n");
        return 1;
    }

    size_t candidate_len = strcspn(line, "\r\n");
    line[candidate_len] = '\0';

    if (candidate_len == sizeof line - 1 && feof(stdin) == 0)
    {
        int extra;
        while ((extra = getchar()) != '\n' && extra != EOF)
        {
        }

        printf("License rejected: the key is longer than this tool supports.\n");
        return 1;
    }

    if (validate_license(line, candidate_len, encoded, encoded_len) != 0)
    {
        printf("License accepted. Northstar License Manager is now registered.\n");
        return 0;
    }

    printf("License rejected: the key does not match the installed license data.\n");
    return 1;
}
