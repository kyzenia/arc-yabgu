// yabgu.c
// https://github.com/kyzenia

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>

static UINT oldInCP, oldOutCP;

static void restoreConsole(void) {
    SetConsoleCP(oldInCP);
    SetConsoleOutputCP(oldOutCP);
}

static void initConsole(void) {
    oldInCP = GetConsoleCP();
    oldOutCP = GetConsoleOutputCP();
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    atexit(restoreConsole);
}

static wchar_t *toWide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = malloc(n * sizeof(wchar_t));
    if (w && MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static FILE *openFile(const char *name, const char *mode) {
    wchar_t *wName = toWide(name);
    wchar_t *wMode = toWide(mode);
    FILE *f = NULL;
    if (wName && wMode) f = _wfopen(wName, wMode);
    free(wName);
    free(wMode);
    return f;
}

static int removeFile(const char *name) {
    wchar_t *w = toWide(name);
    if (!w) { errno = EINVAL; return -1; }
    int r = _wremove(w);
    free(w);
    return r;
}

static char *readLine(char *buf, size_t size) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    if (!GetConsoleMode(h, &mode)) return fgets(buf, (int)size, stdin);   // piped input

    wchar_t w[4096];
    DWORD got = 0;
    if (!ReadConsoleW(h, w, 4095, &got, NULL) || got == 0) return NULL;

    while (got > 0 && (w[got - 1] == L'\r' || w[got - 1] == L'\n')) got--;

    int n = 0;
    if (got > 0) {
        n = WideCharToMultiByte(CP_UTF8, 0, w, (int)got, buf, (int)size - 2, NULL, NULL);
        if (n <= 0) n = 0;
    }
    buf[n] = '\n';
    buf[n + 1] = '\0';
    return buf;
}
#else
#define initConsole() ((void)0)
#define openFile fopen
#define removeFile remove
#define readLine(b, s) fgets((b), (int)(s), stdin)
#endif

#define DATA_CHUNKS (8 * 1024 * 1024)
#define MAX_KEY_DIGITS 4000

char userFile[4096];

int getUserChoice(void);
void getUserFile(char userFile[], size_t size);
long long getUserSeed(void);
size_t getUserKey(unsigned char key[]);
void checkOverflow(void);

typedef struct abGen {
    unsigned char alfaBetas[10][256];
    unsigned char revAlfaBetas[10][256];
} abGen;

abGen alfaBetaGen(long long userSeed);

typedef struct Tables {
    unsigned char tables[10][256];
} Tables;

Tables encryptTableGen(abGen ab);
Tables decryptTableGen(abGen ab);

int cryptFile(unsigned char tables[10][256], const unsigned char key[], size_t lenKey,
              const char inName[], const char outName[]);

void pressEnter(void);
void credits(void);

int main(void) {
    initConsole();
    printf("\n_________________________________________________________");
    printf("\n                                                         ");
    printf("\n                        Yabgu v2.0                       ");
    printf("\n                                                         ");
    printf("\n    Please select among available options below (1-3):   ");
    printf("\n                                                         ");
    printf("\n                     1) Encrypt File                     ");
    printf("\n                     2) Decrypt File                     ");
    printf("\n                     3) Exit                             ");
    printf("\n_________________________________________________________\n\n");

    int userChoice = getUserChoice();
    if (userChoice == 3) {
        credits();
        return 0;
    }

    getUserFile(userFile, sizeof(userFile));

    char outFile[sizeof(userFile) + 8];
    if (userChoice == 1) {
        snprintf(outFile, sizeof(outFile), "%s.yabgu", userFile);
    } else {
        size_t len = strlen(userFile);
        size_t sfx = strlen(".yabgu");
        if (len <= sfx || strcmp(userFile + len - sfx, ".yabgu") != 0) {
            printf("\nThat file doesn't end with \".yabgu\", so it can't be decrypted.\n");
            printf("\nPlease press enter to exit the program...");
            pressEnter();
            return 1;
        }
        snprintf(outFile, sizeof(outFile), "%.*s", (int)(len - sfx), userFile);
    }

    FILE *test = openFile(outFile, "rb");
    if (test) {
        fclose(test);
        printf("\n\"%s\" already exists. Move or rename it first.\n", outFile);
        printf("\nPlease press enter to exit the program...");
        pressEnter();
        return 1;
    }

    long long userSeed = getUserSeed();
    unsigned char key[MAX_KEY_DIGITS];
    size_t lenKey = getUserKey(key);

    abGen ab = alfaBetaGen(userSeed);
    Tables t = (userChoice == 1) ? encryptTableGen(ab) : decryptTableGen(ab);

    int ok = cryptFile(t.tables, key, lenKey, userFile, outFile);

    if (ok) {
        int removeErr = 0;
        if (removeFile(userFile) != 0) removeErr = errno;

        printf("\n%s complete. Please check \"%s\"\n",
                userChoice == 1 ? "Encryption" : "Decryption", outFile);

        if (removeErr != 0) {
            printf("\n>>> WARNING!");
            printf("\nCouldn't delete the original file \"%s\" (%s).", userFile, strerror(removeErr));
            printf("\nPlease delete it manually.\n");
        }
    } else {
        removeFile(outFile);
        printf("\nThere has been a problem while %s. Operation aborted.\n",
               userChoice == 1 ? "encrypting" : "decrypting");
    }

    credits();
    return 0;
}

int getUserChoice(void) {
    long userChoice;
    char buffer[64];
    char *endPtr;

    while (1) {
        printf("Your selection: ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) exit(1);
        if (strchr(buffer, '\n') == NULL) {
            checkOverflow();
            continue;
        }
        userChoice = strtol(buffer, &endPtr, 10);
        if (endPtr != buffer && *endPtr == '\n' && userChoice >= 1 && userChoice <= 3) {
            return (int)userChoice;
        }
        printf("\nIt can't be that hard to enter a valid selection...\n\n");
    }
}

void getUserFile(char userFile[], size_t size) {
    
    int escape = 1;

    do {
        while (1) {
            printf("Enter your file's full name: ");
            if (readLine(userFile, size) == NULL) exit(1);
            if (strchr(userFile, '\n') == NULL) {
                checkOverflow();
                continue;
            }
            char *newline = strchr(userFile, '\n');
            *newline = '\0';
            break;
        }
    
        FILE *file = openFile(userFile, "rb");
        if (file) {
            fclose(file);
            escape = 0;
        } else {
            printf("\n>>> WARNING!");
            printf("\nThere's no such file named \"%s\" in the same directory with the program executable.\n\n", userFile);
            escape = 1;
        }
    } while (escape);
}

long long getUserSeed(void) {
    char buffer[64];
    char *endPtr;

    while (1) {
        printf("Enter your seed (integer): ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) exit(1);
        if (strchr(buffer, '\n') == NULL) {
            checkOverflow();
            continue;
        }
        errno = 0;
        long long userSeed = strtoll(buffer, &endPtr, 10);
        if (endPtr != buffer && *endPtr == '\n' && errno == 0) {
            return userSeed;
        }
        printf("\nIt can't be that hard to enter a valid seed...\n\n");
    }
}

size_t getUserKey(unsigned char key[]) {
    char buffer[MAX_KEY_DIGITS + 2];

    while (1) {
        printf("Enter your key (integer): ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) exit(1);

        char *newline = strchr(buffer, '\n');
        if (newline == NULL) {
            checkOverflow();
            continue;
        }
        *newline = '\0';

        size_t len = strlen(buffer);
        size_t i = 0;
        while (i < len && buffer[i] >= '0' && buffer[i] <= '9') i++;

        if (len > 0 && i == len) {
            for (i = 0; i < len; i++) key[i] = buffer[i] - '0';
            return len;
        }
        printf("\nIt can't be that hard to enter a valid key...\n\n");
    }
}

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint32_t randBelow(uint64_t *state, uint32_t n) {
    uint64_t limit = UINT64_MAX - (UINT64_MAX % n);
    uint64_t r;
    do {
        r = splitmix64(state);
    } while (r >= limit);
    return (uint32_t)(r % n);
}

void shuffle(unsigned char chars[], int len, uint64_t *state) {
    for (int j = len - 1; j > 0; j--) {
        int k = (int)randBelow(state, (uint32_t)(j + 1));
        unsigned char temp = chars[j];
        chars[j] = chars[k];
        chars[k] = temp;
    }
}

abGen alfaBetaGen(long long userSeed) {
    abGen ab;

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 256; j++) {
            ab.alfaBetas[i][j] = j;
            ab.revAlfaBetas[i][j] = j;
        }
    }

    uint64_t state = (uint64_t)userSeed;

    for (int i = 0; i < 10; i++) {
        shuffle(ab.alfaBetas[i], 256, &state);
        for (int j = 0; j < 256; j++) {
            ab.revAlfaBetas[i][ab.alfaBetas[i][j]] = j;
        }
    }

    return ab;
}

Tables encryptTableGen(abGen ab) {
    Tables enc;

    for (int i = 0; i < 10; i++) {
        for (int byte = 0; byte < 256; byte++) {
            enc.tables[i][byte] = ab.alfaBetas[i][byte];
        }
    }

    return enc;
}

Tables decryptTableGen(abGen ab) {
    Tables dec;

    for (int i = 0; i < 10; i++) {
        for (int byte = 0; byte < 256; byte++) {
            dec.tables[i][byte] = ab.revAlfaBetas[i][byte];
        }
    }

    return dec;
}

int cryptFile(unsigned char tables[10][256], const unsigned char key[], size_t lenKey,
              const char inName[], const char outName[]) {
    FILE *in = openFile(inName, "rb");
    if (!in) return 0;

    FILE *out = openFile(outName, "wb");
    unsigned char *buf = malloc(DATA_CHUNKS);
    if (!out || !buf) {
        fclose(in);
        if (out) fclose(out);
        free(buf);
        return 0;
    }

    size_t keyPos = 0, n;
    int ok = 1;

    while ((n = fread(buf, 1, DATA_CHUNKS, in)) > 0) {
        for (size_t i = 0; i < n; i++) {
            buf[i] = tables[key[keyPos]][buf[i]];
            if (++keyPos == lenKey) keyPos = 0;
        }
        if (fwrite(buf, 1, n, out) != n) {
            ok = 0;
            break;
        }
    }

    if (ferror(in)) ok = 0;
    free(buf);
    fclose(in);
    if (fclose(out) != 0) ok = 0;
    return ok;
}

void checkOverflow(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    printf("\nIs it really that hard to not overflow the buffer?");
    printf("\nMind you, I really hate dealing with overflows...\n\n");
}

void pressEnter(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void credits(void) {
    printf("\n_________________________________________________________");
    printf("\n                                                         ");
    printf("\n                            #                            ");
    printf("\n                          #                              ");
    printf("\n                        #                                ");
    printf("\n                      #                                  ");
    printf("\n            #       #               #                    ");
    printf("\n            #     #               # #                    ");
    printf("\n            #   #               #   #   #                ");
    printf("\n            # #               #     # #                  ");
    printf("\n            #       #       #       #       #            ");
    printf("\n            # #       #           # #     #              ");
    printf("\n            #   #       #       #   #   #                ");
    printf("\n            #     #       #   #     # #                  ");
    printf("\n            #       #       #       #                    ");
    printf("\n                      #     #                            ");
    printf("\n                        #   #                            ");
    printf("\n                          # #                            ");
    printf("\n                            #                            ");
    printf("\n_________________________________________________________\n\n");
    printf("Have a great day!\nPlease press enter to exit the program...");
    pressEnter();
}