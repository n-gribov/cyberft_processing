/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#ifndef __CORE_H
#define __CORE_H

#include <sstream>
#include <list>
#include <map>
#include <string>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <unistd.h>
#include "stomp.h"
#include "persist.h"
#include "temporary.h"
#include "users.h"

namespace engine
{
    class listener
    {
    public:
        int fd;
        event ev;
        std::string name;
        class core* parent;

        listener(void):fd(-1),parent(NULL) {}

        void close(void)
            { event_del(&ev); ::close(fd); }
    };

    // флаги доступные при отправке сообщений в очередь (внеполосные данные)
    enum
    {
        flag_close_after_finish = 0x00000001            // закрыть соединение после отправки данного сообщения
    };

    // права доступа
    enum
    {
        O_W_INPUT       = 0x00000001,                   // отправка в INPUT
        O_W_OUTPUT      = 0x00000002,                   // отправка в OUTPUT
        O_W_PRIVATE     = 0x00000004,                   // отправка в приватные очереди
        O_W_OTHER       = 0x00000008,                   // отправка в остальные очереди
        O_S_INPUT       = 0x00000010,                   // подписка на INPUT
        O_S_OUTPUT      = 0x00000020,                   // подписка на OUTPUT
        O_S_SELF        = 0x00000040,                   // подписка на одноименную очередь
        O_S_OTHER       = 0x00000080,                   // подписка на остальные очереди
        O_SYSTEM        = 0x00000100                    // мониторинг внутреннего состояния
    };

    // роли
    enum
    {
        ROLE_ALL        = O_W_INPUT|O_W_OUTPUT|O_W_PRIVATE|O_W_OTHER|O_S_INPUT|O_S_OUTPUT|O_S_SELF|O_S_OTHER,   // без ограничений
        ROLE_PUSH       = O_W_INPUT|O_S_SELF,                                                                   // отправка в INPUT и подписка на одноименную очередь
        ROLE_PULL       = O_W_INPUT|O_S_OUTPUT,                                                                 // только подписка на OUTPUT и запись в INPUT
        ROLE_PROXY      = O_W_INPUT|O_S_SELF|O_S_OTHER,                                                         // отправка в INPUT, подписка на все очереди кроме INPUT и OUTPUT
        ROLE_ROUTER     = O_S_INPUT|O_W_OUTPUT|O_W_PRIVATE|O_W_OTHER,                                           // подписка на INPUT, отправка в любые очереди кроме INPUT (в т.ч. приватные)
        ROLE_ADMIN      = ROLE_ALL|O_SYSTEM                                                                     // полный контроль, включая мониторинг
    };

    enum
    {
        st_wait_for_login       = 1,                                            // ожидается логин
        st_ready                = 2,                                            // готов к приему команд или оправке клиенту нового сообщения
        st_wait_for_ack         = 3                                             // ожидание подтверждения последнего сообщения
    };

    class connection
    {
    public:
        event ev;                                                               // дескриптор событий ввода-вывода libevent
        listener* parent;                                                       // указатель на прослушивающий сокет из которого пришел клиент
        stomp::parser proto;                                                    // парсер STOMP

        short last_event;                                                       // кэш что б лишний раз не переустанавливать события

        int st;                                                                 // состояние сессии
        int fd;                                                                 // сокет клиента
        std::string addr;                                                       // адрес клиента
        u_int32_t session;                                                      // идентификатор сессии
        std::string identity;                                                   // идентификатор клиента из поля login запроса CONNECT
        temporary::queue queue_out;                                             // очередь в памяти сообщений готовых к отправке (размер ограниченый т.к. надо максимум на 1-2 сообщения)
        temporary::queue queue;                                                 // временная приватная очередь на диске ассоциированная с сессией (sessions[sin].queue.push_front(...))

        std::string buffer;                                                     // текущее отправляемое сообщение
        int bytes_sent;                                                         // количество отправленных из buffer данных
        bool close_after_finish;                                                // после отправки текущего сообщения завершить сессию
        bool eof;                                                               // закрыть соединение при первой возможноти

        u_int32_t perm;                                                         // права доступа

        std::map<std::string,persist::queue> subs;                              // на какие очереди подписан клиент (key=имя очереди, value=пара: id подписки, очередь)

        connection(void):parent(NULL),last_event(0),st(0),fd(-1),session(0),bytes_sent(0),close_after_finish(false),eof(false),perm(0) {}

        int set_role(const std::string& s);                                     // установить права доступа (nolimit, push, pull, proxy, router)

        void to_close(void) { eof=true; }

        void close(void)
            { event_del(&ev); ::close(fd); proto.end(); }
    };

    class core : public stomp::callback
    {
    protected:
        event_base* evb;

        event sig_int,sig_quit,sig_term,sig_hup,sig_usr1,sig_usr2;

        std::list<listener> listeners;                                          // список прослушивающих сокетов
        std::map<u_int32_t,connection*> sessions;                               // список всех активных сессий
        persist::storage pdb;                                                   // база данных с очередями
        users::list udb;                                                        // база данный с пользователями и правами

        std::map<std::string, std::list<connection*> > subs;                    // список подписчиков на каждую очередь (key=имя очереди, value=список подписчиков)

        bool subscribe(const std::string& qname,                                // подписать клиента на очередь
            connection* c,persist::queue* _q=NULL);

        bool unsubscribe(const std::string& qname,connection* c);               // отписать клиента от очереди

        bool unsubscribe(connection* c);                                        // отписать клиента от всех очередей (при дисконнекте)

        void close(connection* p);                                              // завершить сессию

        void event_reset(connection* c,short event);                            // сменить состояние обытия ассоциированного с сессией

        int post_reply(connection* c,                                           // поставить сообщение в очередь на отправку
            const std::string& data,bool close_after_finish);

        int __onevent(int fd,connection* p,short events);
    public:
        int db_max_queue_size;
        std::string db_type;
        int backlog;
        bool no_login;
    public:
        core(void):evb(NULL),db_max_queue_size(1024),db_type("TreeDB"),backlog(5),no_login(false) {}

        int init(void);

        int open_persist_db(const std::string& path);
        int open_users_db(const std::string& path);

        int listen(const std::string& addr);

        int loop(void)
            { return event_base_dispatch(evb); }

        void done(void);

        int onsignal(int sig);
        int onaccept(int fd,listener* p);
        int onevent(int fd,connection* p,short events);
        int onstomp(const std::string& command,const std::list<std::string>& headers,std::string& data,void* ctx);
    };

    void openlog(const char* ident,const char* facility);
    void log(const char* fmt,...);
}


#endif
