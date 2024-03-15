/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#ifndef __TEMPORARY_H
#define __TEMPORARY_H

#include <string>
#include <list>

namespace temporary
{
    class data
    {
    public:
        u_int32_t flags;
        std::string value;
    public:
        data(void):flags(0) {}
    };

    class queue
    {
    protected:
        std::list<data> list;
        int cur_size;
    public:
        int max_size;
    public:
        queue(void):cur_size(0),max_size(32) {}

        ~queue(void) {}

        // поместить в очередь значение
        bool push_front(std::string& value,u_int32_t flags=0)
        {
            if(cur_size>=max_size)
                return false;

            list.push_front(data());

            data& d=list.front();

            d.flags=flags;

            d.value.swap(value);

            cur_size++;

            return true;
        }

        // забрать из очереди очередной элемент
        bool pop_back(std::string& value,u_int32_t* flags=NULL)
        {
            if(cur_size<1)
                return false;

            data& d=list.back();

            d.value.swap(value);

            if(flags)
                *flags=d.flags;

            list.pop_back();

            cur_size--;

            return true;
        }

        // получить количество элементов в очереди
        u_int32_t size(void) { return cur_size; }

        // очистить
        bool clear(void)
            { cur_size=0; list.clear(); return true; }
    };

}

#endif

