/* 
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#include "persist.h"
#include <unistd.h>

namespace persist
{
    using namespace kyotocabinet;

    struct global_meta_data {
        u_int32_t max_queue_size; // максимальное количество элементов в одной циклической очереди
        u_int32_t count;          // текущее количество очередей в хранилище (используется при автоматической "нарезке" на именованные очереди)
    };

    struct meta_data {
        u_int64_t write_idx;  // текущая позиция записи
        u_int64_t read_idx;   // текущая позиция чтения
        u_int32_t count;      // текущее количество элементов в очереди
        u_int64_t start_pos;  // стартовая позиция очереди (определяется при создании нового файла, после этого не переопределяется)
        u_int64_t end_pos;    // граница очереди (определяется при создании нового файла, после этого не переопределяется)
    };

    bool storage::open(const std::string& path, const std::string& type, u_int32_t max, bool sync)
    {
        if (type=="HashDB") {
			db = new kyotocabinet::HashDB;
		} else if (type=="TreeDB") {
			db = new kyotocabinet::TreeDB;
		}

        if (!db) {
            return false;
		}

        if (db->open(path, BasicDB::OWRITER|BasicDB::OCREATE)) {
            // Если база новая, то добавляем туда структуру для хранения метаданных
            global_meta_data gmeta;
			memset((char*)&gmeta, 0, sizeof(gmeta));
            gmeta.max_queue_size = max;
            db->add("@", 1, (char*)&gmeta, sizeof(gmeta));
            hard_transaction = sync;
            location = path;

            return true;
        }

        delete db;
        db = NULL;

        return false;
    }

    void storage::close(bool _remove)
    {
        if (db) {
            db->close();
            delete db;
            db = NULL;

            if(_remove) {
                unlink(location.c_str());
			}
        }
    }

    bool storage::get_queue_by_index(u_int32_t idx, queue& q)
    {
        meta_data meta;

        // ищем есть ли в БД очередь с таким индексом
        if (db->get((char*)&idx, sizeof(idx), (char*)&meta, sizeof(meta)) != sizeof(meta)) {
            // если нет, то создаем новую
            global_meta_data gmeta;
            if (db->get("@", 1, (char*)&gmeta, sizeof(gmeta)) != sizeof(gmeta)) {
                return false;
			}

            memset((char*)&meta, 0, sizeof(meta));

            meta.start_pos = meta.write_idx = meta.read_idx = idx * gmeta.max_queue_size;
            meta.end_pos = meta.start_pos + gmeta.max_queue_size;

            // пытаемся начать транзакцию изменения БД
            if (!db->begin_transaction(hard_transaction)) {
                return false;
			}

            // пишем метаданные новой очереди
            if (!db->set((char*)&idx, sizeof(idx), (char*)&meta, sizeof(meta))) {
                db->end_transaction(false);
				return false;
			}

            // коммитим транзакцию
            if (!db->end_transaction(true)) {
                return false;
			}
        }

        q.db = db;
        q.key = idx;
        q.hard_transaction = hard_transaction;

        return true;
    }

    bool storage::get_queue_by_name(const std::string& name, queue& q)
    {
        std::string key;
		key.reserve(name.length() + 2);
        key += '@';
		key += name;
		key += '@';

        u_int32_t idx = 0;

        // ищем индекс очереди с таким алиасом
        if (db->get(key.c_str(), key.length(), (char*)&idx, sizeof(idx)) != sizeof(idx)) {
            // если нет, подбираем новый индекс и создаем новую очередь
            global_meta_data gmeta;
            if (db->get("@", 1, (char*)&gmeta, sizeof(gmeta)) != sizeof(gmeta)) {
                return false;
			}

            idx = gmeta.count++;

            meta_data meta;
            memset((char*)&meta, 0, sizeof(meta));

            meta.start_pos = meta.write_idx = meta.read_idx = idx * gmeta.max_queue_size;
            meta.end_pos = meta.start_pos + gmeta.max_queue_size;

            // пытаемся начать транзакцию изменения БД
            if (!db->begin_transaction(hard_transaction)) {
                return false;
			}

            // пишем метаданные новой очереди
            if (
				!db->set((char*)&idx, sizeof(idx), (char*)&meta, sizeof(meta))
				|| !db->set("@", 1, (char*)&gmeta, sizeof(gmeta))
				|| !db->set(key.c_str(), key.length(), (char*)&idx,sizeof(idx))
			) {
				db->end_transaction(false);
				return false;
			}

            // коммитим транзакцию
            if (!db->end_transaction(true)) {
                return false;
			}

        }

        q.db = db;
        q.key = idx;
        q.hard_transaction = hard_transaction;

        return true;
    }

    u_int32_t queue::size(void)
    {
        if (!db) {
            return 0;
		}

        // пытаемся получить метаданные
        meta_data meta;
        if (db->get((char*)&key, sizeof(key), (char*)&meta, sizeof(meta)) != sizeof(meta)) {
            return 0;
		}

        return meta.count;
    }

    bool queue::clear(void)
    {
        if (!db) {
            return false;
		}

        // пытаемся получить метаданные
        meta_data meta;
        if (db->get((char*)&key, sizeof(key), (char*)&meta, sizeof(meta)) != sizeof(meta)) {
            return false;
		}

        meta.write_idx = meta.read_idx = meta.start_pos;
        meta.count = 0;

        // пытаемся начать транзакцию изменения БД
        if (!db->begin_transaction(hard_transaction)) {
            return false;
		}

        // пишем метаданные
        if (!db->set((char*)&key, sizeof(key), (char*)&meta, sizeof(meta))) {
            db->end_transaction(false);
			return false;
		}

        // коммитим транзакцию
        if (!db->end_transaction(true)) {
            return false;
		}

        return true;
    }

    bool queue::push_front(const std::string& value, int max_num, int* cur_num)
    {
        if (!db) {
            return false;
		}

        // пытаемся получить метаданные
        meta_data meta;
        if (db->get((char*)&key, sizeof(key), (char*)&meta, sizeof(meta)) != sizeof(meta)) {
            return false;
		}

        // ограничение количества сообщений в очереди
        if (max_num > 0 && meta.count >= (u_int32_t)max_num) {
            return false;
		}

        // текущая позиция
        u_int64_t cur_idx=meta.write_idx;

        // смещаем позицию записи на один
        meta.write_idx++;

        // очередь полна, ошибка, ничего не изменяем, в т.ч. указатели остаются на своих местах
        if (meta.write_idx == meta.read_idx || (meta.read_idx == meta.start_pos && meta.write_idx == meta.end_pos)) {
            return false;
		}

        // если позиция записи вышла за допустимые пределы перескакиваем в начало
        if (meta.write_idx == meta.end_pos) {
            meta.write_idx = meta.start_pos;
		}

        // увеличиваем значение счетчика элементов в очереди
        meta.count++;

        // пытаемся начать транзакцию изменения БД
        if (!db->begin_transaction(hard_transaction)) {
            return false;
		}

        // пишем префикс
        if (!db->set((char*)&cur_idx, sizeof(cur_idx), value.c_str(), value.length())) {
			db->end_transaction(false);
			return false;
		}

        // пишем метаданные
        if (!db->set((char*)&key, sizeof(key), (char*)&meta, sizeof(meta))) {
			db->end_transaction(false);
			return false;
		}

        // коммитим транзакцию
        if (!db->end_transaction(true)) {
            return false;
		}

        if (cur_num) {
            *cur_num=meta.count;
		}

        return true;
    }

    bool queue::pop_back(std::string& value)
    {
        value.clear();

        if (!db) {
            return false;
		}

        // пытаемся получить метаданные
        meta_data meta;
        if (db->get((char*)&key, sizeof(key), (char*)&meta, sizeof(meta)) != sizeof(meta)) {
            return false;
		}

        // если позиция чтения вышла за допустимые пределы перескакиваем в начало
        if (meta.read_idx == meta.end_pos) {
            meta.read_idx = meta.start_pos;
		}

        // очередь пуста, ошибка, ничего не изменяем, в т.ч. указатели остаются на своих местах
        if (meta.read_idx == meta.write_idx) {
            return false;
		}

        // текущая позиция
        u_int64_t cur_idx=meta.read_idx;

        // смещаем позицию чтения на один
        meta.read_idx++;

        // уменьшаем значение счетчика элементов в очереди
        meta.count--;

        // пытаемся начать транзакцию изменения БД
        if (!db->begin_transaction(hard_transaction)) {
            return false;
		}

        // читаем значение и удаляем эелемент
        if (!db->get(std::string((char*)&cur_idx, sizeof(cur_idx)), &value)) {
            value.clear();
		}

        db->remove((char*)&cur_idx, sizeof(cur_idx));

        // сохраняем метаданные
        if (!db->set((char*)&key, sizeof(key), (char*)&meta, sizeof(meta))) {
            db->end_transaction(false);
			return false;
		}

        // коммитим транзакцию
        if (!db->end_transaction(true)) {
            return false;
		}

        return true;
    }

    u_int32_t storage::size(void)
    {
        global_meta_data gmeta;
        if (db->get("@", 1, (char*)&gmeta, sizeof(gmeta)) != sizeof(gmeta)) {
			return 0;
		}

        return gmeta.count;
    }

    bool storage::list(std::stringstream& ss)
    {
        if (!db) {
            return false;
		}

        DB::Cursor* cur = db->cursor();

        if (!cur) {
            return false;
		}

        cur->jump();

        std::string key, value;

        while (cur->get(&key, &value, true)) {
            if (key.length() > 2 && key[0] == '@' && key[key.length() - 1] == '@') {
                ss << key.substr(1, key.length() - 2) << '\n';
			}
        }

        delete cur;

        return true;
    }
}
