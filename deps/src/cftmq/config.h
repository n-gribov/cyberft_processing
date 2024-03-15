#ifndef __CONFIG_H
#define __CONFIG_H

#include <map>
#include <string>

namespace cfg
{
    extern std::map<std::string,std::string> p;

    int load(const std::string& s);
}

#endif
