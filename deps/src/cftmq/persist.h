/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#ifndef __PERSIST_H
#define __PERSIST_H

#include <sys/types.h>
#include <sstream>
#include <kchashdb.h>

namespace persist
{
    class queue
    {
    protected:
        kyotocabinet::BasicDB* db;

        bool hard_transaction;

        u_int32_t key;
    public:
        queue(void):db(NULL),hard_transaction(false),key(0) {}

        ~queue(void) {}

        // поместить в очередь значение
        bool push_front(const std::string& value,int max_num,int* cur_num);

        // забрать из очереди очередной элемент
        bool pop_back(std::string& value);

        // получить количество элементов в очереди
        u_int32_t size(void);

        // узнать индекс очереди
        u_int32_t index(void) { return key; }

        // очистить
        bool clear(void);

        friend class storage;
    };

    class storage
    {
    protected:
        kyotocabinet::BasicDB* db;

        bool hard_transaction;

        std::string location;
    public:
        storage(void):db(NULL),hard_transaction(false) {}

        ~storage(void) {}

        // открыть файл БД
        // path: путь к файлу
        // type: тип базы (HashDB или TreeDB)
        // max: максимальное количество элементов в циклической очереди (влияет только на этапе создания новой БД)
        // sync: принудительная синхронизация с диском (true повышает отказоустойчивость но влияет на производительность)
        bool open(const std::string& path,const std::string& type,u_int32_t max,bool sync=false);

        // получить неименованную очередь по индексу
        bool get_queue_by_index(u_int32_t idx,queue& q);

        // получить именованную очередь по имени (если такой нет, то в БД под нее выделяется новый сегмент)
        bool get_queue_by_name(const std::string& name,queue& q);

        // закрыть файл БД (при необходимости с удалением)
        void close(bool _remove=false);

        // общее количество очередей
        u_int32_t size(void);

        // список очередей (разделитель - '\n')
        bool list(std::stringstream& ss);
    };
}

#endif

