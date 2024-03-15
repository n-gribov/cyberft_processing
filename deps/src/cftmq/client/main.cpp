#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stompc.h"

void env_error(const char* name) {
    fprintf(stderr, "%s environment variable is not found\n", name);
    exit(1);
}

int main(int argc, char** argv) {
    const char* addr = getenv("CFT_ADDRESS");
    if (!addr) {
        env_error("CFT_ADDRESS");
    }

    const char* login = getenv("CFT_LOGIN");
    if (!login) {
        env_error("CFT_LOGIN");
    }

    const char* queue = getenv("CFT_QUEUE");
    if (!queue) {
        env_error("CFT_QUEUE");
    }

    const char* pass = getenv("CFT_PASSCODE");
    if (!pass) {
        pass = "";
    }

    const char* hdrs = getenv("CFT_HEADERS");
    if (!hdrs) {
        hdrs = "";
    }

    stomp::connection c;

    bool is_ok = false;

    if (c.connect(addr)) {
        if (c.login(login, pass)) {
            stomp::frame f("SEND");

            for (const char* p1 = hdrs, *p2; p1; p1 = p2) {
                std::string field;
                p2 = strchr(p1, ';');

                if (p2) {
                    field.assign(p1, p2 - p1);
                    p2++;
                } else {
                    field.assign(p1);
                }

                if (!field.empty()) {
                    std::string::size_type n = field.find_first_of("=:");
                    if (n != std::string::npos) {
                        f.hdrs[field.substr(0, n)] = field.substr(n + 1);
                    }
                }
            }

            f.hdrs["destination"] = queue;
            f.hdrs["receipt"] = "0";
            FILE* fp = stdin;

            if (argc > 1) {
                fp = fopen(argv[1], "rb");
            }

            if (fp) {
                char buf[1024];
                size_t n;
                while((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
                    f.data.append(buf, n);
                }
                if (c.send(f) && c.recv(f) && f.command == "RECEIPT") {
                    is_ok = true;
                }

                if (fp != stdin) {
                    fclose(fp);
                }
            }

            c.logout();
        }
    }

    if (is_ok) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
    }

    return 0;
}
