#include "config.h"
#include <stdio.h>
#include <string.h>

namespace cfg
{
    std::map<std::string, std::string> p;

    std::string trim(const std::string& s)
    {
        const char* p1 = s.c_str();
        const char* p2 = p1 + s.length();

        while(*p1 && (*p1 == ' ' || *p1 == '\t')) {
            p1++;
		}

        while(p2 > p1 && (p2[-1] == ' ' || p2[-1] == '\t')) {
            p2--;
		}

        return std::string(p1, p2 - p1);
    }
}

int cfg::load(const std::string& s)
{
    FILE* fp = fopen(s.c_str(), "r");

    if (!fp) {
        return -1;
	}

    char buf[512];

    while (fgets(buf, sizeof(buf), fp)) {
        char* p = strpbrk(buf, "#\r\n");

        if (p) {
			*p=0;
		}

        p = strchr(buf, '=');

        if (p) {
            *p=0;
			p++;
            cfg::p[trim(buf)] = trim(p);
        }
    }

    fclose(fp);

    return 0;
}
