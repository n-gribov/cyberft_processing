/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#ifndef __STOMP_H
#define __STOMP_H

#include <string>
#include <list>
#include <sstream>

namespace stomp
{
    class callback
    {
    public:
        virtual int onstomp(const std::string& command,const std::list<std::string>& headers,std::string& data,void* ctx)=0;
    };

    class parser
    {
    protected:
        enum { max_command_length=16, max_header_length=256, max_headers_num=32, max_data_length=30*1024*1024 };

        int st;

        std::string command;
        std::string header;
        std::list<std::string> headers;
        std::stringbuf data;
        int data_size;
        int headers_num;

        void push_header(void)
            { headers.push_back(std::string()); std::string& s=headers.back(); s.swap(header); headers_num++; }

        void clear(void);

        callback* parent;
        void* ctx;
    public:
        parser(void):st(0),data_size(0),headers_num(0),parent(NULL),ctx(NULL) {}

        int begin(callback* _parent,void* _ctx);

        int parse(const char* s,int len);

        int end(void);
    };
}


#endif
