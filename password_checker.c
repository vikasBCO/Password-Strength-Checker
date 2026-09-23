#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_PASSWORD_LENGTH 99

typedef struct {
    int length;
    int uppercase;
    int lowercase;
    int digit;
    int special;
    int score;
} PasswordAnalysis;

/* Analyze password characteristics */
PasswordAnalysis analyze_password(const char *password) {
    PasswordAnalysis result = {0};

    result.length = (int)strlen(password);

    for (int i = 0; password[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)password[i];

        if (isupper(ch)) {
            result.uppercase = 1;
        } else if (islower(ch)) {
            result.lowercase = 1;
        } else if (isdigit(ch)) {
            result.digit = 1;
        } else {
            result.special = 1;
        }
    }

    /*
     * Score calculation:
     * Length       -> 0-2 points
     * Uppercase    -> 1 point
     * Lowercase    -> 1 point
     * Digit        -> 1 point
     * Special char -> 1 point
     */
    if (result.length >= 8)
        result.score += 2;
    else if (result.length >= 6)
        result.score += 1;

    result.score += result.uppercase;
    result.score += result.lowercase;
    result.score += result.digit;
    result.score += result.special;

    return result;
}

/* Detect repeated characters such as aaa or 111 */
int has_repeated_characters(const char *password) {
    for (int i = 0; password[i + 2] != '\0'; i++) {
        if (password[i] == password[i + 1] &&
            password[i] == password[i + 2]) {
            return 1;
        }
    }

    return 0;
}

/* Detect simple sequential patterns such as abc, 123, xyz */
int has_sequential_pattern(const char *password) {
    for (int i = 0; password[i + 2] != '\0'; i++) {
        unsigned char a = (unsigned char)password[i];
        unsigned char b = (unsigned char)password[i + 1];
        unsigned char c = (unsigned char)password[i + 2];

        if ((b == a + 1 && c == b + 1) ||
            (b == a - 1 && c == b - 1)) {
            return 1;
        }
    }

    return 0;
}

/* Display detailed password analysis */
void display_analysis(const char *password) {
    PasswordAnalysis result = analyze_password(password);

    int repeated = has_repeated_characters(password);
    int sequential = has_sequential_pattern(password);

    printf("\nPassword Analysis\n");
    printf("-------------------------\n");

    printf("%s Length      : %s\n",
           result.length >= 8 ? "✔" : "✘",
           result.length >= 8 ? "Good" : "Minimum 8 characters required");

    printf("%s Uppercase   : %s\n",
           result.uppercase ? "✔" : "✘",
           result.uppercase ? "Present" : "Missing");

    printf("%s Lowercase   : %s\n",
           result.lowercase ? "✔" : "✘",
           result.lowercase ? "Present" : "Missing");

    printf("%s Number      : %s\n",
           result.digit ? "✔" : "✘",
           result.digit ? "Present" : "Missing");

    printf("%s Special Char : %s\n",
           result.special ? "✔" : "✘",
           result.special ? "Present" : "Missing");

    printf("%s Repeated Char: %s\n",
           repeated ? "✘" : "✔",
           repeated ? "Detected" : "Not detected");

    printf("%s Sequential   : %s\n",
           sequential ? "✘" : "✔",
           sequential ? "Detected" : "Not detected");

    /* Penalize predictable patterns */
    if (repeated)
        result.score--;

    if (sequential)
        result.score--;

    if (result.score < 0)
        result.score = 0;

    printf("\nSecurity Score: %d/6\n", result.score);

    if (result.score >= 5 && !repeated && !sequential) {
        printf("Result : STRONG PASSWORD\n");
    } else if (result.score >= 3) {
        printf("Result : MEDIUM PASSWORD\n");
    } else {
        printf("Result : WEAK PASSWORD\n");
    }

    /* Actionable suggestions */
    if (result.length < 8)
        printf("- Increase the password length to at least 8 characters.\n");

    if (!result.uppercase)
        printf("- Add at least one uppercase letter.\n");

    if (!result.lowercase)
        printf("- Add at least one lowercase letter.\n");

    if (!result.digit)
        printf("- Add at least one number.\n");

    if (!result.special)
        printf("- Add at least one special character.\n");

    if (repeated)
        printf("- Avoid repeating the same character three or more times.\n");

    if (sequential)
        printf("- Avoid predictable sequences such as abc or 123.\n");
}

int main(void) {
    char password[MAX_PASSWORD_LENGTH + 1];

    printf("====================================\n");
    printf("     PASSWORD STRENGTH CHECKER\n");
    printf("====================================\n");

    printf("Enter Password: ");

    /*
     * fgets prevents buffer overflow and also allows
     * spaces inside the password.
     */
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Error: Unable to read password.\n");
        return 1;
    }

    /* Remove trailing newline */
    password[strcspn(password, "\n")] = '\0';

    if (strlen(password) == 0) {
        printf("Error: Password cannot be empty.\n");
        return 1;
    }

    display_analysis(password);

    return 0;
}
