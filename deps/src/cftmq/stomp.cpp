/* 
 * STOMP Parser Class
 *
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#include "stomp.h"
#include <stdio.h>

int stomp::parser::begin(stomp::callback* _parent, void* _ctx) {
    clear();

    command.reserve(max_command_length);
    header.reserve(max_header_length);
    data_size = 0;
    headers_num = 0;
    parent = _parent;
    ctx = _ctx;

    return 0;
}

int stomp::parser::end(void) {
    if (st != 0 || !command.empty() || !header.empty() || !headers.empty() || data_size > 0) {
        return -1;
    }

    clear();

    return 0;
}

void stomp::parser::clear(void) {
    command.clear();
    header.clear();
    headers.clear();
    data.str(std::string());
    data_size = 0;
    headers_num = 0;
    st = 0;
}

int stomp::parser::parse(const char* s, int len) {
    for (int i = 0; i < len; i++) {
        int ch = ((const unsigned char*) s)[i];
        switch(st) {
            // ожидаем названия команды
            case 0:
                // пропускаем переводы строк
                if (ch == '\r' || ch == '\n' || ch == 0) {
                    continue;
                }
                // начало тела команды, накапливаем
                command += ch;
                // и переходим в состояние считывания команды
                st = 1;
                break;
            // считываем команду
            case 1:
                if (ch == '\r') {
                    // пропуск \r и ожидание \n
                    st = 2;
                    continue;
                } else if (ch == '\n') {
                    // конец команды, ждем заголовков
                    st = 10;
                    header.clear();
                    continue;
                }

                if (command.length() >= max_command_length) {
                    // слишком длинная команда
                    return -1;
                }
                // продолжаем накапливать команду
                command += ch;
                break;
            // получено \r, ожидание \n после команды
            case 2:
                if (ch != '\n') {
                    return -1;
                } else {
                    // конец команды, ждем заголовков
                    st = 10;
                    header.clear();
                }
                break;
            // ждем заголовков
            case 10:
                if (ch == '\r') {
                    // заголовков нет, ждем \n
                    st = 11;
                    continue;
                } else if (ch == '\n') {
                    // конец заголовка
                    if (header.empty()) {
                        // пустой заголовок, ждем тело
                        st = 20;
                    } else {
                        if (headers_num >= max_headers_num) {
                            // слишком много заголовков
                            return -1;
                        }
                        // cохраняем и ждем следующий заголовок
                        push_header();
                    }
                    continue;
                }
            
                if (header.length() >= max_header_length) {
                    // слишком длинный заголовок
                    return -1;
                }
                // Накопить текущий заголовок
                header += ch;
                if (ch == ':') {
                    // пропуск потенциальных пробелов перед телом заголовка
                    st = 12;
                }
                break;
            // ожидание \n после заголовка
            case 11:
                if (ch != '\n') {
                    return -1;
                }

                if (header.empty()) {
                    // пустой заголовок, ждем тело
                    st = 20;
                } else {
                    // Проверка на макс. количество заголовков
                    if (headers_num >= max_headers_num) {
                        return -1;
                    }
                    // сохранить текущий заголовок
                    push_header();
                    // ждем следующий заголовок
                    st = 10;
                }

                break;
            // пропуск пробелов перед телом заголовка
            case 12:
                if (ch == ' ') {
                    continue;
                } else if (ch == '\n') {
                    // конец заголовка
                    if (header.empty()) {
                        // пустой заголовок, ожидаем тело
                        st = 20;
                    } else {
                        if (headers_num >= max_headers_num) {
                            // слишком много заголовков
                            return -1;
                        }
                        // сохранить текущий заголовок
                        push_header();
                        // ожидать новый заголовок
                        st = 10;
                    }
                } else if (ch == '\r') {
                    // ожидать \n
                    st = 11;
                } else {
                    if (header.length() >= max_header_length) {
                        // слишком длинный заголовок
                        return -1;
                    }
                    // накопить текущий заголовок
                    header += ch;
                    // продолжать ожидать заголовок
                    st = 10;
                }
                break;
            // накапливаем тело
            case 20:
                if (ch == 0) {
                    // конец фрейма - требуется обработка
                    if (parent) {
                        std::string s = data.str();
                        parent->onstomp(command, headers, s, ctx);
                    }
#ifdef TRY_PARSER
                    printf("command: '%s'\n", command.c_str());
                    for (std::list<std::string>::iterator it = headers.begin(); it != headers.end(); ++it) {
                        printf("header: '%s'\n", it->c_str());
                    }
                    printf("data [%i]: '%s'\n", data_size, data.str().c_str());
#endif
                    st = 0;
                    clear();
                    continue;
                }

                if (data_size >= max_data_length) {
                    return -1;
                }

                data.sputc(ch);
                data_size++;

                break;
        }
    }

    return 0;
}

#ifdef TRY_PARSER

int main(void)
{
    stomp::parser p;

    const char buf[] =
        "MESSAGE\r\n"
        "test1: value1\n"
        "test2: value2\r\n"
        "test3:value3\n"
        "test4:value4\r\n"
        "test5: \n"
        "test6: \r\n"
        "test7:\n"
        "test8:\r\n"
        "\r\n"
        "hello world\000";

    p.begin(NULL, NULL);

    if (p.parse(buf,sizeof(buf) - 1) || p.parse(buf, sizeof(buf) - 1) || p.end()) {
        printf("ERR\n");
    }

    return 0;
}
#endif
