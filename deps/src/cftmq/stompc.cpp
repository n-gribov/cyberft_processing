/**
 * Stomp Connection Class
 *
*/

#include "stompc.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

bool stomp::connection::connect(const std::string& addr) {
    std::string::size_type n=addr.find(':');

    if (n == std::string::npos) {
        return false;
    }

    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(addr.substr(n + 1).c_str()));
    sin.sin_addr.s_addr = inet_addr(addr.substr(0, n).c_str());

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        hostent* he = gethostbyname(addr.substr(0, n).c_str());
        if (he) {
            memcpy((char*) &sin.sin_addr.s_addr, he->h_addr, sizeof(sin.sin_addr.s_addr));
        }
    }

    if (sin.sin_addr.s_addr == INADDR_NONE || !sin.sin_port) {
        return false;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if(fd != -1) {
        if (!::connect(fd, (sockaddr*) &sin, sizeof(sin))) {
            int on = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
            fp = fdopen(fd, "a+");
            if (fp) {
                return true;
            }
        }

        ::close(fd);
    }

    return false;
}

void stomp::connection::close(void) {
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
}

bool stomp::connection::send(const frame& f) {
    if (fprintf(fp, "%s\n", f.command.c_str()) < 0) {
        return false;
    }

    for (
        std::map<std::string, std::string>::const_iterator i = f.hdrs.begin();
        i != f.hdrs.end();
        ++i
    ) {
        if (fprintf(fp, "%s:%s\n", i->first.c_str(), i->second.c_str()) < 0) {
            return false;
        }
    }
    if (fprintf(fp, "content-length:%i\n\n", (int) f.data.length()) < 0) {
        return false;
    }

    if (fwrite(f.data.c_str(), f.data.length() + 1, 1, fp) != 1) {
        return false;
    }

    if (!fflush(fp)) {
        return true;
    }

    return false;
}

bool stomp::connection::recv(frame& f) {
    f.clear();
    char buf[256];
    for (int idx = 0;;) {
        if (!fgets(buf, sizeof(buf), fp)) {
            return false;
        }

        char* p = strchr(buf, '\n');
        if (!p) {
            return false;
        }
        *p=0;
        if (!idx) {
            if (!*buf) {
                continue;
            }
            f.command.assign(buf, p - buf);
            idx++;
        } else {
            if (!*buf) {
                break;
            }

            char* p2 = strchr(buf, ':');

            if (p2) {
                *p2 = 0;
                p2++;
                f.hdrs[buf].assign(p2, p - p2);
            }
        }
    }

    std::map<std::string,std::string>::const_iterator it = f.hdrs.find("content-length");

    if (it != f.hdrs.end()) {
        int len = atoi(it->second.c_str());
        if (len > 0) {
            f.data.reserve(len);
        }
    }

    for (;;) {
        int ch = fgetc(fp);
        if (ch == EOF || ch == 0) {
            break;
        }
        f.data += ch;
    }

    return true;
}

bool stomp::connection::login(const std::string& username, const std::string& passcode) {
    stomp::frame f("CONNECT");
    f.hdrs["login"] = username;
    f.hdrs["passcode"] = passcode;

    if (send(f) && recv(f) && f.command == "CONNECTED") {
        return true;
    }

    return false;
}

bool stomp::connection::logout(void) {
    stomp::frame f("DISCONNECT");
    f.hdrs["receipt"] = "0";

    if (send(f) && recv(f) && f.command == "RECEIPT") {
        return true;
    }

    return false;
}

bool stomp::connection::subscribe(const std::string& destination) {
    stomp::frame f("SUBSCRIBE");
    f.hdrs["destination"] = destination;
    f.hdrs["ack"] = "client";
    f.hdrs["receipt"] = "0";

    if (send(f) && recv(f) && f.command == "RECEIPT") {
        return true;
    }

    return false;

}

bool stomp::connection::unsubscribe(const std::string& destination)
{
    stomp::frame f("UNSUBSCRIBE");
    f.hdrs["destination"] = destination;
    f.hdrs["receipt"] = "0";

    if (send(f) && recv(f) && f.command == "RECEIPT") {
        return true;
    }

    return false;
}

bool stomp::connection::ack(const std::string& msgid) {
    stomp::frame f("ACK");
    f.hdrs["message-id"] = msgid;

    if (send(f)) {
        return true;
    }

    return false;
}

bool stomp::connection::send(const std::string& msg, const std::string& destination) {
    stomp::frame f("SEND");
    f.hdrs["destination"] = destination;
    f.hdrs["receipt"] = "0";
    f.data = msg;

    if (send(f) && recv(f) && f.command == "RECEIPT") {
        return true;
    }

    return false;
}
