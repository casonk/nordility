#define _GNU_SOURCE

#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static const char expected[] = "v1.Sample_TOKEN-+~AZ09";

int main(int argc, char **argv)
{
    struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
    struct termios original;
    struct termios hidden;
    char token[128];

    if (argc == 4 && strcmp(argv[1], "set") == 0 &&
        strcmp(argv[2], "analytics") == 0 && strcmp(argv[3], "off") == 0) {
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "settings") == 0) {
        fputs("User Consent: disabled\n", stdout);
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "login") != 0 || strcmp(argv[2], "--token") != 0) {
        return 2;
    }

    fputs("Enter access token: ", stdout);
    fflush(stdout);

    /* Deliberately widen the real CLI's prompt-before-ReadPassword race. */
    usleep(250000);
    if (poll(&input, 1, 0) != 0) {
        return 3;
    }
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
        return 4;
    }
    hidden = original;
    hidden.c_lflag &= (tcflag_t) ~(ECHO | ECHONL);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) != 0) {
        return 5;
    }
    if (fgets(token, sizeof(token), stdin) == NULL) {
        return 6;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &original);
    token[strcspn(token, "\r\n")] = '\0';
    if (strcmp(token, expected) != 0) {
        return 7;
    }

    /* Hostile child output must never escape the helper. */
    fprintf(stdout, "server echoed token: %s\n", token);
    fflush(stdout);
    usleep(750000);
    return 0;
}
