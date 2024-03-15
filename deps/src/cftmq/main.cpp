/* 
 * Event driven STOMP broker with Kyoto Cabinet persist
 * Protocol version: STOMP 1.0
 * Anton Burdinuk, 2014
 * clark15b@gmail.com
 */

#include <stdio.h>
#include <unistd.h>
#include "core.h"
#include "config.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

// Метод разрешает запись дамп-файла
void enable_core_dump(void)
{
    rlimit l;
	// Получить лимиты размера дамп-файла
    if (!getrlimit(RLIMIT_CORE, &l)) {
		// Установить софт-лимит равный хард-лимиту
        l.rlim_cur = l.rlim_max;
		// Установить лимиты размера дамп-файла
        setrlimit(RLIMIT_CORE, &l);
    }
}

// Главный метод
int main(int argc,char** argv)
{
	// Разрешить запись дамп-файла
    enable_core_dump();
	// Путь к файлу конфигурации
    std::string cfg_path;
	// Флаг завершения
    bool terminate = false;
	// Флаг помощи
    bool help = false;
	// Флаг работы на переднем плане
    bool foreground = false;

	// Если параметров меньше 2, вывод хелпа
    if (argc < 2) {
        help = true;
    } else {
        int opt;
		// Получить ключи из командной строки
        while((opt = getopt(argc, argv, "c:fth?")) > 0) {
            switch(opt) {
				// Путь к файлу конфигурации
                case 'c': cfg_path = optarg; break;
				// Флаг зщавершения
                case 't': terminate = true; break;
				// Флаг работы на переднем плане
                case 'f': foreground = true; break;
				// Флаг помощи
                default: help = true; break;
            }
        }
    }

	// Получение имени программы из параметра командной строки, поиск разделителя "/"
    const char* self = strrchr(argv[0], '/');

    if (self) {
		// Если найден разделитель, имя после него
        self++;
    } else {
		// Иначе имя это сам параметр
        self = argv[0];
    }

	// Если затребована помощь или путь к файлу конфигурации не задан
    if (help || cfg_path.empty()) {
		// Вывод помощи
        fprintf(stderr,
            "\nEvent driven STOMP broker with Kyoto Cabinet persist\n"
            "Protocol version: STOMP 1.0\n\n"
            "Anton Burdinuk, 2014\n"
            "clark15b@gmail.com\n\n"
            "USAGE: ./%s [-t] [-f] -c config_path\n"
            "-t   terminate\n"
            "-f   foreground\n\n",self);
		// Выход
        exit(0);
    }

	// Загрузка файла конфигурации
    if (cfg::load(cfg_path)) {
        fprintf(stderr, "can't load config file '%s'\n", cfg_path.c_str());
        exit(1);
    }

	// Переход в папку spool
    chdir(cfg::p["spool"].c_str());

	// Имя pid-файла
    const std::string& pid_file = cfg::p["pid_file"];
	// Значение pid
    pid_t pid=0;
	// Если pid-файл не пустой
    if (!pid_file.empty()) {
		// Открыть файл
        FILE* fp = fopen(pid_file.c_str(), "r");
		// Прочитать значение pid из файла
        if (fp) {
            fscanf(fp, "%u", &pid);
            fclose(fp);
        }
    }
	// Если запрошено завершение
    if (terminate) {
		// Если нет pid, завершать нечего
        if (!pid) {
            fprintf(stderr, "stopped.\n");
        } else {
            fprintf(stderr, "found, pid=%u... ", pid);
			// Завершить процесс
            if (!kill(pid,SIGTERM)) {
                fprintf(stderr,"terminate.");
            } else {
				// Вывод кода ошибки
                perror("kill");
            }
            fprintf(stderr,"\n");
        }
		// Выход
        exit(0);
    }

	// Если есть pid, программа уже запущена
    if (pid) {
        fprintf(stderr, "already running, pid=%u\n", pid);
		// Выход
        exit(1);
    }

	// Если запуск не на переднем плане
    if (!foreground) {
		// Форкнуть процесс и получить новый pid 
        pid_t pid = fork();
		// Неудачный форк
        if (pid == (pid_t) -1) {
			// Вывод кода ошибки
            perror("fork");
			// Выход
            exit(1);
        }
		// Удачный форк
        if (pid) {
			// Выход
            exit(0);
        }
    }

	// Это происходит уже в форкнутом процессе либо в процессе на переднем плане
	// Если pid-файл не пустой
    if (!pid_file.empty()) {
		// Открыть файл на запись
        FILE* fp = fopen(pid_file.c_str(), "w");
		// Получить и записать pid процесса в файл
        if (fp) {
            fprintf(fp,"%u",getpid());
            fclose(fp);
        }
    }

	// Инстанциация основного ядра
    engine::core core;

	// Открыть лог
    engine::openlog(cfg::p["log_ident"].c_str(), cfg::p["log_facility"].c_str());
    engine::log("initialize...");

	// Инициализировать ядро
    if (!core.init()) {
		// Задать масимальный размер очереди
        core.db_max_queue_size = atoi(cfg::p["db_max_queue_size"].c_str());
        if (core.db_max_queue_size < 1) {
            core.db_max_queue_size = 1;
        }
		// Задать тип базы данных
        core.db_type=cfg::p["db_type"];
		// Задать тип бэклога
        core.backlog=atoi(cfg::p["backlog"].c_str());
        if (core.backlog < 1) {
            core.backlog = 1;
        }
		// Задать флаг отсутствия логина
        if (cfg::p["no_login"] == "true") {
            core.no_login = true;
        } else {
            core.no_login = false;
        }
		// Открыть персист-базу и базу пользователей
        if (!core.open_persist_db(cfg::p["persist_db"]) && !core.open_users_db(cfg::p["users_db"])) {
			// Начать слушать порт
            core.listen(cfg::p["listen"]);
            engine::log("initialized");
			// Начать цикл работы
            core.loop();
        }
		// Завершить работу ядра
        core.done();
    }

	// Если pid-Файл не пустой, удалить его
    if (!pid_file.empty()) {
        unlink(pid_file.c_str());
    }

    engine::log("bye.");

    return 0;
}
