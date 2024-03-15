#ifndef __STOMPC_H
#define __STOMPC_H

#include <stdio.h>
#include <string>
#include <map>

namespace stomp
{
    class frame
    {
    public:
        std::string command;
        std::map<std::string,std::string> hdrs;
        std::string data;

        frame(void) {}

        frame(const std::string& _command,const std::string& _data=std::string()):command(_command),data(_data) {}

        void clear(void) { command.clear(); hdrs.clear(); data.clear(); }
    };

    class connection
    {
    protected:
        FILE* fp;

    public:
        connection(void):fp(NULL) {}
        ~connection(void) { close(); }

        bool connect(const std::string& addr);

        bool login(const std::string& username,const std::string& passcode);

        bool logout(void);

        bool subscribe(const std::string& destination);

        bool unsubscribe(const std::string& destination);

        bool send(const std::string& msg,const std::string& destination);

        bool send(const frame& f);

        bool recv(frame& f);

        bool ack(const std::string& msgid);

        void close(void);

        bool empty(void) { return fp?false:true; }
    };
}


#endif
