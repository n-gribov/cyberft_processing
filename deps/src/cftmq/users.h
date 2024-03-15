#ifndef __USERS_H
#define __USERS_H

#include <kchashdb.h>
#include <stdio.h>

enum alg_t {ALG_MD5, ALG_SHA256};

namespace users
{
    using namespace kyotocabinet;

    class user
    {
    protected:
        alg_t _alg;
        std::string _passcode;
        std::string _salt;
        std::string _role;
    public:
        user(void) {}

        std::string role(void) { return _role; }

        bool validate(const std::string& passcode);

        friend class list;
    };

    class list
    {
    protected:
        BasicDB* db;
        std::string location;
        std::string cache_location;

        bool parse(FILE* fp);
    public:
        list(void):db(NULL) {}

        bool open(const std::string& source_path,const std::string& cache_path);

        bool reload(void) { close(); return open(location,cache_location); }

        bool get(const std::string& name,user& u);

        void close(void);
    };
}


#endif
