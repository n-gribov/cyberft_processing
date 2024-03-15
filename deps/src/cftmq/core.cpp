/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#include "core.h"
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>

// Класс с методами ядра

namespace engine
{
	// Коллбэк на закрытие сокета
    void event_quit_signal_callback_fn(evutil_socket_t fd, short events, void* arg)
	{
        event_base_loopbreak((event_base*) arg);
    }

	// Коллбэк на сигнал сокета
    void event_signal_callback_fn(evutil_socket_t fd, short events, void* arg)
	{
        ((engine::core*)arg)->onsignal((int) fd);
    }

	// Коллбэк на входящее соединение
    void event_accept_callback_fn(evutil_socket_t fd, short events, void* arg)
	{
        ((engine::listener*)arg)->parent->onaccept(fd, (engine::listener*) arg);
	}

	// Коллбэк на событие сокета
    void event_callback_fn(evutil_socket_t fd, short events, void* arg)
	{
        ((engine::connection*)arg)->parent->parent->onevent(fd, (engine::connection*) arg, events);
    }

	// Метод открывает логирование
    void openlog(const char* ident, const char* facility)
	{
        const char* p = facility;

        int f = LOG_SYSLOG;
		// Выбор движка лога
        if (!strncmp(p, "local", 5)) {
            if (p[5] > 47 && p[5] < 56 && !p[6]) {
                f = ((16 + (p[5] - 48)) << 3);
            }
        } else if (!strcmp(p, "daemon")) {
            f = LOG_DAEMON;
        }

		::openlog(ident, LOG_PID, f);
    }

	// Метод пишет в лог
    void log(const char* fmt, ...)
	{
        va_list ap;

        va_start(ap, fmt);
        vsyslog(LOG_INFO, fmt, ap);
        va_end(ap);
    }

	// Метод получает ip-адрес сокета по имени
    int getaddrbyname(const std::string& addr, sockaddr_in& sin)
    {
        std::string host, port;
        std::string::size_type n = addr.find(':');
		// Если найдена ":", то адрес разбивается на хост и порт
        if (n != std::string::npos) {
            host = addr.substr(0, n);
            port = addr.substr(n + 1);
        } else {
			// Иначе порт это адрес
            port = addr;
        }

        sin.sin_family = AF_INET;

		// Задание адреса сокета
        if (!host.length() || host == "*") {
            sin.sin_addr.s_addr = INADDR_ANY;
        } else {
            sin.sin_addr.s_addr = inet_addr(host.c_str());
        }

		// Задание опрта сокета
        sin.sin_port = htons(atoi(port.c_str()));

#ifdef __FreeBSD__
        sin.sin_len = sizeof(sin);
#endif /* __FreeBSD__ */

		// Адрес не задался
        if (sin.sin_addr.s_addr == INADDR_NONE) {
            return -1;
        }

        return 0;
    }

	// Метод получает ид сессии
    u_int32_t getsessid(void)
	{
		// Статическая переменная counter увеличивается на 1 при каждом вызове
        static u_int32_t counter = 0;

		// При переполнении сбрасывается на 0
        if (counter == 0xffffffff) {
            counter = 0;
        }
		// Инкремент и возврат значения
        return ++counter;
    }

	// Метод получает ид сообщения
    std::string getmessid(void)
	{
		// Статическая переменная counter увеличивается на 1 при каждом вызове
        static u_int32_t counter = 0;

		// При переполнении сбрасывается на 0
        if (counter == 0xffffffff) {
            counter=0;
        }
		// Инкремент и перевод числа в строку
        char buf[64];
        int n = sprintf(buf, "%u", ++counter);

        return std::string(buf, n);
    }
}

// Метод устанавливает роль
int engine::connection::set_role(const std::string& s)
{
    if (s == "nolimit" || s == "free" || s == "all") {
        perm = ROLE_ALL;
    } else if (s == "push" || s == "restricted") {
        perm = ROLE_PUSH;
    } else if (s == "pull") {
        perm = ROLE_PULL;
    } else if (s == "proxy") {
        perm = ROLE_PROXY;
    } else if (s == "router") {
        perm = ROLE_ROUTER;
    } else if(s == "admin") {
        perm = ROLE_ADMIN;
    } else {
        return -1;
    }

    return 0;
}

// Инициализация ядра
int engine::core::init(void)
{
    evb = event_base_new();

    if (!evb) {
        return -1;
    }

	// Назначение обработчиков событий
    event_assign(&sig_int, evb, SIGINT, EV_SIGNAL|EV_PERSIST, event_quit_signal_callback_fn, evb);
    event_add(&sig_int, NULL);

    event_assign(&sig_quit, evb, SIGQUIT, EV_SIGNAL|EV_PERSIST, event_quit_signal_callback_fn, evb);
    event_add(&sig_quit, NULL);

    event_assign(&sig_term, evb, SIGTERM, EV_SIGNAL|EV_PERSIST, event_quit_signal_callback_fn, evb);
    event_add(&sig_term, NULL);

    event_assign(&sig_hup, evb,SIGHUP, EV_SIGNAL|EV_PERSIST, event_signal_callback_fn, this);
    event_add(&sig_hup, NULL);

    event_assign(&sig_usr1, evb, SIGUSR1, EV_SIGNAL|EV_PERSIST, event_signal_callback_fn, this);
    event_add(&sig_usr1, NULL);

    event_assign(&sig_usr2, evb,SIGUSR2, EV_SIGNAL|EV_PERSIST, event_signal_callback_fn, this);
    event_add(&sig_usr2, NULL);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    return 0;
}

// Метод открывает персист-базу
int engine::core::open_persist_db(const std::string& path)
{
    if (!pdb.open(path, db_type, db_max_queue_size, false)) {
        return -1;
    }

    log("open '%s' as persist queue", path.c_str());

    return 0;
}

// Метод открывает базу пользователей
int engine::core::open_users_db(const std::string& path)
{
    std::string::size_type n = path.find_last_of('/');
    std::string cache_name;

    if (n != std::string::npos) {
        cache_name = path.substr(n + 1);
    } else {
        cache_name = path;
    }

    if (!udb.open(path, cache_name + ".db")) {
        return -1;
    }

    log("open '%s' as user database", path.c_str());

    return 0;
}

// Метод завершает работу ядра
void engine::core::done(void)
{
    if (!evb) {
        return;
    }
	// Закрытие слушателей
    for (std::list<listener>::iterator it = listeners.begin(); it != listeners.end(); ++it) {
        it->close();
    }
	// Закрытие сессий
    for (std::map<u_int32_t, connection*>::iterator it = sessions.begin(); it != sessions.end(); ++it) {
        it->second->close();
    }

	// Очистка списка слушателей и сессий
    listeners.clear();
    sessions.clear();

	// Отмена обработчиков событий
    event_del(&sig_int);
    event_del(&sig_quit);
    event_del(&sig_term);
    event_del(&sig_hup);
    event_del(&sig_usr1);
    event_del(&sig_usr2);

    event_base_free(evb);
    evb = NULL;

	// Закрытие персист-базы и базы пользователей
    pdb.close();
    udb.close();
}

// Метод сбрасывает событие
void engine::core::event_reset(connection* c, short event)
{
    if (event == c->last_event) {
        return;
    }
    c->last_event = event;
    event_del(&c->ev);
    event_assign(&c->ev, evb, c->fd, event|EV_PERSIST, event_callback_fn, c);
    event_add(&c->ev, NULL);
}

// Метод прослушивает входящее соединение
int engine::core::listen(const std::string& addr)
{
    sockaddr_in sin;

	// Получить адрес сокета
    if (getaddrbyname(addr,sin)) {
        return -1;
    }

	// Получить ресурс сокета
    int fd = socket(PF_INET,SOCK_STREAM, 0);

    if (fd == -1) {
        return -2;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	// Неблокирующие операции
    fcntl(fd, F_SETFL, O_NONBLOCK);

	// Привязать сокет к ресурсу
    if (!bind(fd, (sockaddr*) &sin, sizeof(sin))) {
		// Начать прослушивание
        if (!::listen(fd, backlog)) {
			// Добавить сокет в список слушателей
            listeners.push_back(listener());
            listener& l = listeners.back();

            l.fd = fd;
            l.name = addr;
            l.parent = this;

			// НАстроить обработчик события на входящее соединение
            event_assign(&l.ev, evb, l.fd, EV_READ|EV_PERSIST, event_accept_callback_fn, &l);
            event_add(&l.ev, NULL);

            log("listen '%s'", addr.c_str());

            return 0;
        }
    }

    ::close(fd);

    return -3;
}

// Метод обработки сигналов
int engine::core::onsignal(int sig)
{
    if (sig == SIGHUP) {
        log("reload user database - %s", udb.reload() ? "OK" : "FAIL");
    }

    return 0;
}

// Метод обработки входящего соединения
int engine::core::onaccept(int fd, engine::listener* p)
{
    for (;;) {
        sockaddr_in sin;
        socklen_t sin_len = sizeof(sin);

		// Новый сокет
        int newfd = accept(fd, (sockaddr*) &sin, &sin_len);

        if (newfd == -1) {
            break;
        }

        fcntl(newfd, F_SETFL, O_NONBLOCK);
        int on = 1;
        setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        u_int32_t sid = 0;

        for (int i = 0; i < 10; i++) {
            u_int32_t s = getsessid();

            if (sessions.find(s) == sessions.end()) {
                sid=s;
                break;
            }
        }

        if (!sid) {
            ::close(newfd);
            continue;
        }

        connection* c = new connection;

        if (!c) {
            ::close(newfd);
            continue;
        }

        sessions[sid] = c;

        c->session = sid;
        c->fd = newfd;
        c->addr = inet_ntoa(sin.sin_addr);
        c->parent = p;
        event_assign(&c->ev, evb, c->fd, EV_READ|EV_PERSIST, event_callback_fn, c);
        event_add(&c->ev, NULL);

        c->proto.begin(this, (void*)c);

        if (no_login) {
            c->set_role("nolimit");
            c->identity = "noname";
            c->st = st_ready;
        } else {
            c->st = st_wait_for_login;
        }

        log("connection from '%s'", c->addr.c_str());
    }

    return 0;
}

// Метод обработки события
int engine::core::onevent(int fd, engine::connection* p, short events)
{
    try {
        return __onevent(fd, p, events);
    } catch(...) {}

    // если что не так с исключениями просто закрываем соединение
    try {
        close(p);
    } catch(...) {}

    return -1;
}

// Метод обработки события
int engine::core::__onevent(int fd, engine::connection* p, short events)
{
    if (events & EV_READ) {
        // не стоит читать от одного клиента до бесконечности, ограничимся 4к (4*1024)
        for (int i = 0; i < 4 && !p->eof; i++) {
            char buf[1024];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n == (ssize_t) - 1) {
                if (errno == EAGAIN) {
                    break;
                } else {
                    p->eof = true;
                }
            } else if (!n) {
                p->eof = true;
            } else if (p->proto.parse(buf, n)) {
                p->eof = true;
            }
        }
    }

    if (!p->eof && events & EV_WRITE) {
        bool again = false;
        while(!again && !p->eof) {
            if (p->buffer.empty()) {
                u_int32_t flags = 0;

                if (p->queue_out.pop_back(p->buffer, &flags)) {
                    p->bytes_sent = 0;
                    if (flags & flag_close_after_finish) {
                        p->close_after_finish = true;
                    }
                } else {
                    // ничего нет - засыпаем для этого клиента до пинка
                    event_reset(p, EV_READ);
                    break;
                }
            }

            const char* ptr = p->buffer.c_str();

            int length = p->buffer.length() + 1;

            while(!p->eof && p->bytes_sent < length) {
                ssize_t n = write(p->fd, ptr + p->bytes_sent, length - p->bytes_sent);
                if (n == (ssize_t) -1) {
                    if (errno == EAGAIN) {
                        // писать некуда - засыпаем для этого клиента пока не появится место
                        // (до очередного EV_WRITE)
                        again = true;
                        break;
                    } else {
                        p->eof = true;
                    }
                } else if (!n) {
                    p->eof = true;
                } else {
                    p->bytes_sent += n;
                }
            }

            if (p->bytes_sent >= length) {
                // сообщение отправленно полностью
                p->buffer.clear();
                if (p->close_after_finish) {
                    // если была команда закрыть соединение - закрываем, в противном случае
                    // возвращаемся и смотрим нет ли еще сообщений
                    p->eof = true;
                }
                // принудительно ограничимся одним сообщением за итерацию
                // (если убрать, то не остановится пока не отправит все что скопилось в очереди
                // для одного клиента)
                again = true;
            }
        }
    }

    if (p->eof) {
        close(p);
    }

    return 0;
}

// Метод отправки ответа
int engine::core::post_reply(engine::connection* c, const std::string& data, bool close_after_finish)
{
    u_int32_t flags = 0;

    if (close_after_finish) {
        flags |= flag_close_after_finish;
    }

    std::string s(data);

    if (c->queue_out.push_front(s, flags)) {
        event_reset(c, EV_READ | EV_WRITE);
    }

    return 0;
}

// Метод подписки на очередь
bool engine::core::subscribe(const std::string& qname, connection* c, persist::queue* _q)
{
    persist::queue q;

    if (!pdb.get_queue_by_name(qname, q)) {
        return false;
    }

    std::map<std::string,persist::queue>::const_iterator it = c->subs.find(qname);

    if (it! = c->subs.end()) {
        // уже подписан
        return false;
    }

    c->subs[qname] = q;
    subs[qname].push_back(c);

    if (_q) {
        *_q = q;
    }

    return true;
}

// Метод закрытия соединения
void engine::core::close(connection* p)
{
    log("close connection to '%s'", p->addr.c_str());
    unsubscribe(p);
    p->close();
    delete p;
    sessions.erase(p->session);
}

// Метод отписки от очереди
bool engine::core::unsubscribe(const std::string& qname, connection* c)
{
    std::map<std::string,persist::queue>::iterator it = c->subs.find(qname);

    if (it == c->subs.end()) {
        // не подписан
        return false;
    }

    c->subs.erase(it);
    // не очень оптимально при большом количестве подписчиков (чего никогда не будет)
    subs[qname].remove(c);

    return true;
}

// Метод отписки от всех очередей
bool engine::core::unsubscribe(connection* c)
{
    for (
        std::map<std::string, persist::queue>::iterator it = c->subs.begin();
        it != c->subs.end();
        ++it
    ) {
        subs[it->first].remove(c);
    }

    c->subs.clear();

    return true;
}

// Метод обработки STOMP
int engine::core::onstomp(
    const std::string& command,
    const std::list<std::string>& headers,
    std::string& data,
    void* ctx
) {
    connection* c = (connection*) ctx;
    std::map<std::string, std::string> hdr;

    // парсим заголовки в мэп hdr
    for (
        std::list<std::string>::const_iterator it = headers.begin();
        it != headers.end();
        ++it
    ) {
        const std::string& s = *it;
        std::string::size_type n = s.find(':');
        if (n != std::string::npos) {
            hdr[s.substr(0, n)] = s.substr(n + 1);
        }
    }

    // ждем команду CONNECT или STOMP
    if (c->st == st_wait_for_login) {
        if (command != "CONNECT" && command != "STOMP") {
            post_reply(c, "ERROR\ncontent-type:text/plain\n\nNot connected\n", true);
        } else {
            bool ok = false;
            const std::string& login = hdr["login"];
            const std::string& passcode = hdr["passcode"];
            users::user u;

            if (!login.empty() && udb.get(login, u) && u.validate(passcode)) {
                if (!c->set_role(u.role())) {
                    c->identity = login;
                    c->st = st_ready;
                    ok = true;
                }
            }

            if (ok) {
                log(
                    "connected '%s' as '%s' (sid=%u, addr='%s')",
                    c->identity.c_str(), u.role().c_str(), c->session, c->addr.c_str()
                );

                char buf[256];
                int n = sprintf(buf,"CONNECTED\nsession:%u\n\n", c->session);
                post_reply(c, std::string(buf, n), false);
            } else {
                log(
                    "access denied for '%s' (sid=%u, addr='%s')",
                    login.c_str(), c->session, c->addr. c_str()
                );
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nAccess denied\n", true);
            }
        }

        return 0;
    }

    std::string receipt;
    std::string docid;

    {
        std::map<std::string,std::string>::const_iterator it = hdr.find("receipt");
        if (it != hdr.end()) {
            receipt=it->second;
        }

        if (receipt.length() > 64) {
            receipt = receipt.substr(receipt.length() - 64);
        }

        it = hdr.find("doc_id");
        if (it != hdr.end()) {
            docid = it->second;
        }
    }

    if (command=="SEND") {
        // потенциальный получатель (либо сессия, либо первый свободный подписчик)
        connection* dc = 0;

        // признак того, что сообщение адресовано конкретному получателю (сессии)
        bool direct_message = false;              

        const std::string& destination = hdr["destination"];

        int cur_num = 0; // текущее количество сообщений в очереди
        int max_num = -1; // максимально допустимое количество сообщений в очереди определяемое клиентом

        {
            const std::string& s = hdr["max-num"];
            if (!s.empty()) {
                max_num=atoi(s.c_str());
            }
        }

        bool allow = false;

        static const char sid_tag[] = "sid/";

        if (!destination.empty()) {
            if (destination.substr(0, sizeof(sid_tag) - 1) == sid_tag) {
                // получатель - номер сессии, ищем соответствующего клиента
                if (c->perm & O_W_PRIVATE) {
                    allow = true;
                    direct_message = true;
                    char* endptr = NULL;
                    long long n = strtoll(destination.c_str() + sizeof(sid_tag) - 1, &endptr, 10);

                    if (!*endptr && n > 0 && n <= 0xffffffff) {
                        std::map<u_int32_t,connection*>::iterator it = sessions.find((u_int32_t)n);
                        if (it != sessions.end()) {
                            dc = it->second;
                        }
                    }
                }
            } else {
                // получатель - имя очереди в persist, ищем первого готового подписчика
                if (destination == "INPUT") {
                    if (c->perm & O_W_INPUT) {
                        allow = true;
                    }
                } else if (destination == "OUTPUT") {
                    if (c->perm & O_W_OUTPUT) {
                        allow = true;
                    }
                } else {
                    if (c->perm & O_W_OTHER) {
                        allow = true;
                    }
                }

                if (allow) {
                    std::map<std::string, std::list<connection*> >::iterator it = subs.find(destination);

                    if (it != subs.end()) {
                        std::list<connection*>& lst = it->second;

                        for(std::list<connection*>::iterator i = lst.begin(); i != lst.end(); ++i) {
                            connection* p = *i;
                            if (p->st == st_ready) {
                                dc = p;
                                break;
                            }
                        }
                    }
                }
            }
        }

        bool ok = false;

        std::string mid;

        if (allow && (dc || !direct_message)) {
            // минимальные условия для доставки сообщения
            hdr.erase("content-length");
            hdr.erase("source");

            std::stringstream ss;

            ss << "MESSAGE\n";

            char temp[256];
            int n = snprintf(
                emp, sizeof(temp),
                "reply-to:%s%u\nmessage-id:%s\nsource:%s\nsource-ip:%s\ncontent-length:%lu\n",
                sid_tag, c->session, (mid = getmessid()).c_str(), c->identity.c_str(), c->addr.c_str(),
                data.length()
            );

            if (n == -1 || n >= (int) sizeof(temp)) {
                n = sizeof(temp) - 1;
			}

            ss.write(temp, n);

            for (std::map<std::string, std::string>::const_iterator i = hdr.begin(); i != hdr.end(); ++i) {
                ss << i->first << ':' << i->second << "\n";
			}
	        ss << "\n";
		    ss << data;
			std::string s = ss.str();

			if (dc && dc->st == st_ready) {
				// есть кому непосредственно отдать сообщение, отдаем и пинаем получателя
				if (dc->queue_out.push_front(s)) {
					event_reset(dc, EV_READ | EV_WRITE);
					dc->st = st_wait_for_ack;
					ok = true;
				}
			} else {
				if (direct_message) {
					// сообщение для конкретной сессии, кладем сообщение на "долговременное" хранение и забываем про него
					ok = dc->queue.push_front(s);
				} else {
					persist::queue q;
					if (pdb.get_queue_by_name(destination, q)) {
						// ищем очередь (если ее нет, то она создается)
						// кладем сообщение на долговременное хранение и забываем про него
						ok = q.push_front(s, max_num, &cur_num);
					}
				}
			}
		}

		if (!receipt.empty()) {
			if (ok) {
				char buf[256];
				sprintf(buf, "RECEIPT\nreceipt-id:%s\nqueue-size:%i\n\nOK\n", receipt.c_str(), cur_num);
				post_reply(c, buf, false);
			} else {
				post_reply(c, "ERROR\ncontent-type:text/plain\n\nUnable to dispatch message\n", false);
			}
		}
	} else if (command == "ACK") {
		// пришло подтверждение последнего сообщения - это один из возможных пинков поискать
        // а нет ли чего еще в очередях
        // что именно подтвердили не важно т.к. мы отдаем сообщения только поштучно
        if (c->st == st_wait_for_ack) {
            c->st = st_ready;
            std::string s;
            if (!c->queue.pop_back(s)) {
                // сначала ищем в приватной очереди сессии
                for (
                    std::map<std::string,persist::queue>::iterator it = c->subs.begin();
                    t != c->subs.end();
                    ++it
                ) {
                    if (it->second.pop_back(s)) {
                        // если там пусто, то бежим по всем подпискам пока не найдем где-нибудь чего-нибудь
                        break;
                    }
                }
            }

            if (!s.empty() && c->queue_out.push_front(s)) {
                event_reset(c, EV_READ | EV_WRITE);
                c->st = st_wait_for_ack;
            }
        }
    } else if (command == "SUBSCRIBE") {
        if (hdr["ack"] != "client") {
            if (!receipt.empty()) {
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nOnly 'ack:client' is allowed\n", false);
            }
        } else {
            const std::string& destination = hdr["destination"];
            persist::queue q;
            bool ok = false;
            if (!destination.empty()) {
                bool allow = false;
                if (destination == "INPUT") {
                    if (c->perm & O_S_INPUT) {
                        allow = true;
                    }
                } else if (destination == "OUTPUT") {
                    if (c->perm & O_S_OUTPUT) {
                        allow = true;
                    }
                } else if (destination == c->identity) {
                    if (c->perm & O_S_SELF) {
                        allow = true;
                    }
                } else {
                    if (c->perm & O_W_OTHER) {
                        allow = true;
                    }
                }

                if (allow && subscribe(destination,c,&q)) {
                    ok = true;

                    if (!receipt.empty()) {
                        post_reply(c, "RECEIPT\nreceipt-id:" + receipt + "\n\nOK\n", false);
                    }

                    log(
                        "subscribe '%s' to '%s' (sid=%u, addr='%s')",
                        c->identity.c_str(), destination.c_str(), c->session, c->addr.c_str()
                    );

                    if (c->st == st_ready) {
                        // если готов принимать сообщения, то сразу заглядываем в эту очередь
                        // и выгребаем очередное сообщение
                        std::string s;
                        if (q.pop_back(s) && c->queue_out.push_front(s)) {
                            event_reset(c, EV_READ | EV_WRITE);
                            c->st = st_wait_for_ack;
                        }
                    }
                }
            }

            if (!ok && !receipt.empty()) {
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nUnable to subscribe\n", false);
            }
        }
    } else if (command == "UNSUBSCRIBE") {
        const std::string& destination = hdr["destination"];
        bool ok = false;
        if (!destination.empty() && unsubscribe(destination, c)) {
            ok = true;
            log(
                "unsubscribe '%s' from '%s' (sid=%u, addr='%s')",
                c->identity.c_str(), destination.c_str(), c->session, c->addr.c_str()
            );
        }

        if (!receipt.empty()) {
            if (ok) {
                post_reply(c, "RECEIPT\nreceipt-id:" + receipt + "\n\nOK\n", false);
            } else {
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nUnable to unsubscribe\n", false);
            }
        }
    } else if (command == "DISCONNECT") {
        // клиент заказал безопасное закрытие сессии
        log("disconnect '%s' (sid=%u, addr='%s')", c->identity.c_str(), c->session, c->addr.c_str());
        if (!receipt.empty()) {
			// попросили отчет, поэтому выдаем отчет и закрываем соединение
            post_reply(c, "RECEIPT\nreceipt-id:" + receipt + "\n\nOK\n", true);
        } else {
            // ничего не просил, просто закрываем соединение
            c->to_close();
        }
    } else if (command == "SYSTEM") {
        if (c->perm & O_SYSTEM) {
            std::stringstream ss;
            ss << "SYSTEM\ncontent-type:text/plain\n\n";

            const std::string& cmd = hdr["cmd"];
            if (cmd == "ls") {
                pdb.list(ss);
            } else if (cmd == "count") {
                ss << pdb.size() << '\n';
            } else if (cmd == "size") {
                const std::string& arg = hdr["arg"];
                for(std::string::size_type p1 = 0, p2; p1 != std::string::npos; p1 = p2) {
                    std::string name;
                    p2 = arg.find(',', p1);
                    if (p2 != std::string::npos) {
                        name = arg.substr(p1, p2 - p1);
                        p2++;
                    } else {
                        name = arg.substr(p1);
                    }
                    if (!name.empty()) {
                        persist::queue q;
                        if (pdb.get_queue_by_name(name,q)) {
                            ss << name << ' ' << q.size() << '\n';
                        }
                    }
                }
            }

            post_reply(c, ss.str(), false);
        } else {
            post_reply(c, "ERROR\ncontent-type:text/plain\n\nAccess denied\n", true);
        }
    }
#ifdef WITH_BLOBS
    else if (command == "PUT") {
        // запись фрагмента бинарных данных на диск
        bool ok = false;
        std::string& seq_id = hdr["seq-id"];
        int offset = 0, length = 0;
        off_t total_len = (off_t) -1;
        std::string filename;

        {
            std::string& range = hdr["range"];
            std::string::size_type n = range.find('-');
            if (n!=std::string::npos) {
                offset = atoi(range.substr(0, n).c_str());
                length = atoi(range.substr(n + 1).c_str()) - offset + 1;
            }
        }

        if (
            !c->identity.empty() && !seq_id.empty()
            && c->identity.length() < 64 && seq_id.length() < 64
            && offset >= 0 && length > 0 && (size_t) length == data.length()
            && length <= 1024 * 1024 && offset + length < (1024 * 1024 * 1024)
        ) {
            filename = c->identity + "-" + seq_id + ".blob";
            int fd = open(filename.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (fd != -1) {
                int l = 0;
                if (lseek(fd, offset, SEEK_SET) != (off_t) - 1) {
                    while(l < length) {
                        ssize_t n = write(fd, data.c_str() + l, length - l);
                        if (n == (ssize_t) -1 || n == 0) {
                            break;
                        }
                        l += n;
                    }
                }

                if (l == length) {
                    total_len = lseek(fd, 0, SEEK_END);
                    ok = true;
                }

                ::close(fd);
            }
        }

        if (!receipt.empty()) {
            if (ok) {
                char buf[512];
                sprintf(
                    buf, "RECEIPT\nreceipt-id:%s\nfilename:%s\nlength:%lu\n\nOK\n",
                    receipt.c_str(), filename.c_str(), total_len
                );
                post_reply(c, buf, false);
            } else {
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nCan't do it\n", false);
            }
        }
    } else if(command=="GET") {
        // чтение фрагмента бинарных данных с диска
        bool ok = false;
        std::string& seq_id = hdr["seq-id"];
        int offset = 0, length = 0;
        off_t total_len = (off_t) -1;
        std::string filename;
        std::string ss;

        {
            std::string& range = hdr["range"];
            std::string::size_type n = range.find('-');
            if (n != std::string::npos) {
                offset = atoi(range.substr(0, n).c_str());
                length = atoi(range.substr(n + 1).c_str()) - offset + 1;
            } else {
                offset = atoi(range.c_str());
            }

            if (length <= 0 || length > 1024 * 1024) {
                length = 1024 * 1024;
            }
        }

        if (
            !c->identity.empty() && !seq_id.empty()
            && c->identity.length() < 64 && seq_id.length() < 64
            && offset >= 0 && length >= 0 && length <= 1024 * 1024
        ) {
            filename = c->identity + "-" + seq_id + ".blob";
            int fd = open(filename.c_str(), O_RDONLY);
            if (fd != -1) {
                int l = 0;
                if (lseek(fd, offset, SEEK_SET) != (off_t) -1) {
                    ss.reserve(length);
                    while(l < length) {
                        char buf[1024];
                        ssize_t n = read(fd, buf, sizeof(buf) > (size_t) length ? length : sizeof(buf));
                        if (n == (ssize_t) -1 || n==0) {
                            break;
                        }

                        ss.append(buf, n);
                        l += n;
                    }

                    total_len = lseek(fd, 0, SEEK_END);
                    ok = true;
                }

                ::close(fd);
            }
        }

        if (!receipt.empty()) {
            if (ok) {
                char buf[512];
                int n = sprintf(
                    buf,
                    "RECEIPT\nreceipt-id:%s\ncontent-length:%lu\nfilename:%s\nlength:%lu\n\n",
                    receipt.c_str(), ss.length(), filename.c_str(), total_len
                );
                ss = std::string(buf, n) + ss;
                if (c->queue_out.push_front(ss)) {
                    event_reset(c, EV_READ | EV_WRITE);
                }
            } else {
                post_reply(c, "ERROR\ncontent-type:text/plain\n\nCan't do it\n", false);
            }
        }
    }
#endif /* WITH_BLOBS */
    else {
		// на все неизвестные команды выдаем ошибку и прекращаем взаимодействие
        post_reply(c, "ERROR\ncontent-type:text/plain\n\nNot implemented\n", true);
    }

    return 0;
}
