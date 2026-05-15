#include <stdio.h>
#include <stdlib.h>

int sqlite3_exec(void *db, const char *sql, void *callback, void *arg, char **errmsg);
int PyRun_SimpleString(const char *command);
int curl_easy_setopt(void *curl, int option, const char *parameter);
void send_html(const char *body);

#define CURLOPT_URL 10002

void path_traversal(char *name) {
    char path[512] = {0};
    snprintf(path, sizeof(path), "/tmp/uploads/%s", name);
    FILE *fp = fopen(path, "r");
    if (fp) {
        fclose(fp);
    }
}

void sql_injection(char *user_id) {
    sqlite3_exec(NULL, user_id, NULL, NULL, NULL);
}

void code_injection(char *expr) {
    PyRun_SimpleString(expr);
}

void ssrf(char *url) {
    curl_easy_setopt(NULL, CURLOPT_URL, url);
}

void xss(char *name) {
    char page[512] = {0};
    snprintf(page, sizeof(page), "<p>Hello %s</p>", name);
    send_html(page);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        path_traversal(argv[1]);
        sql_injection(argv[1]);
        code_injection(argv[1]);
        ssrf(argv[1]);
        xss(argv[1]);
    }
    return 0;
}
