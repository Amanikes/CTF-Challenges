/*
 * Aegis Communications — Phantom Protocol client 1.2.0
 *
 * Offline protocol token checker. Reads protocol.dat from the directory that
 * contains this executable, applies the Phantom Protocol transformation to the
 * candidate token and compares it with the encoded payload.
 *
 * The accepted token is never stored in this executable and is never printed.
 */

#define _POSIX_C_SOURCE 200809L

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROTOCOL_FILE "protocol.dat"

/* Container format ------------------------------------------------------- */
#define PROTOCOL_MAGIC_0 'P'
#define PROTOCOL_MAGIC_1 'H'
#define PROTOCOL_MAGIC_2 'T'
#define PROTOCOL_MAGIC_3 'M'
#define PROTOCOL_VERSION 1u
#define PROTOCOL_HEADER_SIZE 8u
#define PROTOCOL_MAX_TOKEN 128u

/* Transformation stages -------------------------------------------------- */
#define STAGE_ADD_BASE 0x2Bu
#define STAGE_ADD_STEP 0x07u
#define STAGE_ROT_BASE 3u
#define STAGE_ROT_STEP 5u

static const uint8_t STAGE_XOR_KEY[] = "AegisPhantomKey!";
#define STAGE_XOR_KEY_LEN (sizeof(STAGE_XOR_KEY) - 1u)

enum load_result
{
    LOAD_OK = 0,
    LOAD_IO_ERROR = 1,
    LOAD_FORMAT_ERROR = 2
};

static uint8_t rotate_left(uint8_t value, unsigned int bits)
{
    bits &= 7u;

    if (bits == 0u)
        return value;

    return (uint8_t)((uint8_t)(value << bits) | (uint8_t)(value >> (8u - bits)));
}

static uint8_t position_addend(size_t index)
{
    return (uint8_t)((STAGE_ADD_BASE + (uint8_t)(index * STAGE_ADD_STEP)) & 0xFFu);
}

static unsigned int position_rotation(size_t index)
{
    return (unsigned int)((STAGE_ROT_BASE + (size_t)(index * STAGE_ROT_STEP)) & 7u);
}

/*
 * Phantom Protocol forward transformation:
 *   1. position-dependent byte addition modulo 256
 *   2. XOR with a repeating key
 *   3. position-dependent bit rotation
 */
__attribute__((noinline, used)) static void transform_token(uint8_t *buffer, size_t length)
{
    for (size_t index = 0; index < length; ++index)
    {
        uint8_t value = buffer[index];
        value = (uint8_t)((value + position_addend(index)) & 0xFFu);
        value = (uint8_t)(value ^ STAGE_XOR_KEY[index % STAGE_XOR_KEY_LEN]);
        value = rotate_left(value, position_rotation(index));
        buffer[index] = value;
    }
}

/*
 * Transform the candidate and compare. The difference accumulator avoids an
 * early exit, so the whole pipeline runs for every candidate.
 */
__attribute__((noinline, used)) static int token_matches(const uint8_t *candidate, size_t candidate_len,
                                                         const uint8_t *payload, size_t payload_len)
{
    if (candidate_len != payload_len)
        return 0;

    if (candidate_len == 0)
        return 0;

    uint8_t working[PROTOCOL_MAX_TOKEN];
    memcpy(working, candidate, candidate_len);
    transform_token(working, candidate_len);

    uint8_t difference = 0;

    for (size_t index = 0; index < candidate_len; ++index)
        difference |= (uint8_t)(working[index] ^ payload[index]);

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

static int load_protocol(const char *path, uint8_t *payload, size_t *payload_len)
{
    FILE *file = fopen(path, "rb");

    if (file == NULL)
        return LOAD_IO_ERROR;

    uint8_t buffer[PROTOCOL_HEADER_SIZE + PROTOCOL_MAX_TOKEN + 1u];
    size_t read = fread(buffer, 1, sizeof buffer, file);
    int trailing = fgetc(file);
    int failed = ferror(file);

    fclose(file);

    if (failed != 0)
        return LOAD_IO_ERROR;

    if (trailing != EOF)
        return LOAD_FORMAT_ERROR;

    if (read < PROTOCOL_HEADER_SIZE)
        return LOAD_FORMAT_ERROR;

    if (buffer[0] != (uint8_t)PROTOCOL_MAGIC_0 || buffer[1] != (uint8_t)PROTOCOL_MAGIC_1 ||
        buffer[2] != (uint8_t)PROTOCOL_MAGIC_2 || buffer[3] != (uint8_t)PROTOCOL_MAGIC_3)
        return LOAD_FORMAT_ERROR;

    if (buffer[4] != (uint8_t)PROTOCOL_VERSION)
        return LOAD_FORMAT_ERROR;

    size_t declared = (size_t)buffer[5];

    if (declared == 0u || declared > (size_t)PROTOCOL_MAX_TOKEN)
        return LOAD_FORMAT_ERROR;

    if (buffer[6] != 0u || buffer[7] != 0u)
        return LOAD_FORMAT_ERROR;

    if (read != PROTOCOL_HEADER_SIZE + declared)
        return LOAD_FORMAT_ERROR;

    memcpy(payload, buffer + PROTOCOL_HEADER_SIZE, declared);
    *payload_len = declared;

    return LOAD_OK;
}

static void print_usage(void)
{
    printf("Aegis Communications Phantom Protocol client 1.2.0\n");
    printf("\n");
    printf("Usage:\n");
    printf("  phantom-client                    show this message\n");
    printf("  phantom-client --verify <token>   verify a protocol token\n");
    printf("\n");
    printf("protocol.dat must be stored next to this executable.\n");
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        print_usage();
        return 0;
    }

    if (argc != 3 || strcmp(argv[1], "--verify") != 0)
    {
        print_usage();
        return 2;
    }

    char directory[PATH_MAX];
    char data_path[PATH_MAX];

    if (executable_directory(directory, sizeof directory) != 0)
    {
        fprintf(stderr, "phantom-client: protocol data rejected: unable to resolve executable path\n");
        return 2;
    }

    if (snprintf(data_path, sizeof data_path, "%s/%s", directory, PROTOCOL_FILE) >= (int)sizeof data_path)
    {
        fprintf(stderr, "phantom-client: protocol data rejected: path too long\n");
        return 2;
    }

    uint8_t payload[PROTOCOL_MAX_TOKEN];
    size_t payload_len = 0;
    int result = load_protocol(data_path, payload, &payload_len);

    if (result == LOAD_IO_ERROR)
    {
        fprintf(stderr, "phantom-client: protocol data rejected: %s could not be read\n", PROTOCOL_FILE);
        return 2;
    }

    if (result != LOAD_OK)
    {
        fprintf(stderr, "phantom-client: protocol data rejected: unsupported or corrupted format\n");
        return 2;
    }

    const char *candidate = argv[2];
    size_t candidate_len = strlen(candidate);

    if (token_matches((const uint8_t *)candidate, candidate_len, payload, payload_len) != 0)
    {
        printf("ACCESS GRANTED\n");
        return 0;
    }

    printf("ACCESS DENIED\n");
    return 1;
}
