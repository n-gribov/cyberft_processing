# Класс роутера для приёма и отправки сообщений

package CyberFT::Router;

use strict;
use utf8;
use Data::Dumper;
use Data::UUID ();
use Convert::PEM ();
use Digest::MD5 ();
use Encode ();
use Time::HiRes ();
use Crypt::OpenSSL::X509 ();
use File::Copy ();
use Time::Local ();
use Date::Calc ();
use POSIX qw(strftime);

use CyberFT::Broker;
use CyberFT::Database;
use CyberFT::Envelope;
use CyberFT::Errors;
use CyberFT::OperatorRole;

# Импорт библиотечных методов
use CyberFT::Utils qw(
    escape_crlf
    remove_crlf
    read_file
    write_file
    dumper
    md5_sum_file
    temp_filename
    timestamp_hires
    gen_timestamps
);

my $MAX_IN_MEMORY_DOC_SIZE = 4 * 1024 * 1024;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
}

# Метод инициализирует роутер
# Обязательные параметры:
#     broker_host, broker_port, broker_username, broker_password, db_data_source, db_username, db_password,
#     sys_id, sys_certificate_file, sys_private_key_file, sys_private_key_password, log_func.
# Здесь параметр log_func - функция логирования. В нее будут передаваться два параметра:
#     уровень ("info", "warning", "error", "debug") и сообщение для записи в лог.
sub init {
    my $self = shift;
    my %params = @_;

    # Конфиг заполняется входными параметрами
    $self->{config} = \%params;

    # Список обязательных параметров
    my @required_params = qw(
        broker_host
        broker_port
        broker_username
        broker_password
        broker_spool_dir
        db_data_source
        db_username
        db_password
        sys_id
        sys_certificate_file
        sys_private_key_file
        sys_private_key_password
        temp_dir
        envelope_max_size
        log_func
    );

    # Проверить наличие обязательных параметров по списку
    for my $p (@required_params) {
        unless ($self->{config}->{$p}) {
            # Если параметр не установлен, вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Required parameter not found: '$p'"};
        }
    }
    # Проверить доступность папок для временных файлов и хранилища брокера
    for my $dir_param ('temp_dir', 'broker_spool_dir') {
        unless (-d $self->{config}->{$dir_param}) {
            # Если параметр не установлен, вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Bad directory parameter: $dir_param"};
        }
    }

    # Залогировать сервисную информацию
    $self->log('info', 'Initialization');
    $self->log('info', 'Self Id: ' . $self->{config}->{sys_id});

    # Подключиться к базе данных
    my $r = $self->connect_database();
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Initialization failed: Database connection error: ' . $r->{ErrMsg});
        # Вернуть результат
        return $r;
    }

    # Подключиться к брокеру сообщений
    my $r = $self->connect_broker();
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Initialization failed: Message broker error: ' . $r->{ErrMsg});
        # Вернуть результат
        return $r;
    }

    # Залогировать сервисную информацию
    $self->log('info', 'Reading signing keys');
    eval {
        # Загрузить системный закрытый ключ
        $self->load_system_private_key();
        # Загрузить системный сертификат для подписи ответных сообщений
        $self->load_system_certificate();
    };
    # Если возникла ошибка
    if (my $err = $@) {
		# Залогировать ошибку
        $self->log('error', 'Initialization failed: System certificate / private key loading error: ' . $err);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'System certificate / private key loading error: ' . $err};
    }
	# Залогировать сервисную информацию
    $self->log('info', 'Initialization is complete');
	# Вернуть результат с успехом
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод открывает соединение с базой данных.
# В случае ошибки пытается переподключаться через определенный интервал времени
sub connect_database {
    my $self = shift;
    # Список входных параметров
    my %params = @_;
    # Количество повторных попыток
    my $retry_count = $params{retry_count}; # если не задано - будет пытаться бесконечно
    # Залогировать сервисную информацию
    $self->log('info', 'Connecting to the database: ' . $self->{config}->{db_data_source});
    # Создать объект доступа к базе данных
    $self->{db} = CyberFT::Database::new_instance($self->{config});

    my $retry_counter = 0; # cчётчик попыток
    my $interval = 5; # 5 секунд
    my $error_message; # сообщение об ошибке
    # Бесконечный цикл
    while (1) {
        # Попытаться получить соединение
        my $db_conn_res = $self->{db}->connect();
        # Если не было ошибки
        if ($db_conn_res->{Result} eq '0') {
            # Вернуть результат с успехом
            return {Result => 0, ErrCode => 0, ErrMsg => ''};
        } elsif (!defined($retry_count) || $retry_counter < $retry_count) {
            # Если не указано количество повторных попыток или они ещё не исчерпаны
            # Залогировать ошибки
            $self->log('error', 'Database connection error: ' . $db_conn_res->{ErrMsg});
            $self->log('error', 'Retrying database connection after: ' . $interval . 's');
            # Увеличить счётчик попыток
            $retry_counter += 1;
            # Сделать паузу длиной в заданный интервал
            sleep($interval);
            # Продолжить цикл
            next;
        }
        # Получить сообщение об ошибке
        $error_message = $db_conn_res->{ErrMsg};
        # Прекратить цикл
        last;
    }
    # Вернуть результат с ошибкой
    return {Result => 1, ErrCode => 10, ErrMsg => $error_message};
}

# Метод проверяет соединение с базой и переподключается при необходимости
# Проверка выполняется через определенные промежутки времени или если выставлен флаг db_check_needed
sub check_database_connection {
    my $self = shift;
    # Интервал проверки
    my $interval = 1 * 60;
    # Если неизвестно время последней проверки или оно устарело
    if (!defined($self->{db_last_checked}) || time() - $self->{db_last_checked} > $interval) {
        # Устновить флаг необходимости проверки
        $self->{db_check_needed} = 1;
    }
    # Если установлен флаг необходимости проверки
    if ($self->{db_check_needed}) {
        # Если нет соединения с базой или она не пингуется
        unless (defined($self->{db}) && $self->{db}->ping()) {
            # Залогировать ошибку
            $self->log('error', 'Database connection lost');
            # Открыть соединение с базой данных
            $self->connect_database();
        }
        # Очистить флаг необходимости проверки
        $self->{db_check_needed} = 0;
        # Установить время последней проверки
        $self->{db_last_checked} = time();
    }
}

# Метод открывает соединение с брокером сообщений
sub connect_broker {
    my $self = shift;
    # Залогировать сервисную информацию
    $self->log('info', 'Connecting to the message broker: ' . $self->{config}->{broker_host} . ':' . $self->{config}->{broker_port});
    # Установить последнее время бездействия брокера
    $self->{broker_idle_timer} = time();
    # Создать объект брокера
    $self->{broker} = CyberFT::Broker->new;
    # Попытаться установить соединение с брокером с конфиг-параметрами
    my $broker_conn_res = $self->{broker}->connect(
        $self->{config}->{broker_host},
        $self->{config}->{broker_port},
        $self->{config}->{broker_username},
        $self->{config}->{broker_password},
        $self->{config}->{log_func},
    );
    # Если возникла ошибка
    if ($broker_conn_res->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Message broker connection error: ' . $broker_conn_res->{ErrMsg});
        # Сохранить ошибку брокера
        $self->save_broker_conn_error();
        # Вернуть результат
        return $broker_conn_res;
    }

    # Залогировать сервисную информацию
    $self->log('info', 'Subscribing to the INPUT queue');
    # Подписаться на очередь INPUT
    my $broker_sub_res = $self->{broker}->subscribe('INPUT');
    # Если возникла ошибка
    if ($broker_sub_res->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Message broker subscribe error: ' . $broker_sub_res->{ErrMsg});
        # Сохранить ошибку брокера
        $self->save_broker_conn_error();
        return $broker_sub_res;
    }
    # Вернуть результат с успехом
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод выполняет переподключение, если от брокера давно не приходило новых сообщений
# Также переподключение выполнится если выставлен флаг $self->{broker_reconnect_needed}
sub check_broker_connection {
    my $self = shift;
    # Интервал
    my $interval = 6 * 60 * 60;
    # Если истёк интервал или требуется переподключение
    if (time() - $self->{broker_idle_timer} > $interval || $self->{broker_reconnect_needed}) {
        # Залогировать сервисную информацию
        $self->log('info', 'Reconnecting to the message broker');
        # Закрыть соединение с брокером
        $self->{broker}->disconnect();
        # Открыть соединение с брокером
        $self->connect_broker();
        # Очистить флаг необходимости реконнекта брокера
        $self->{broker_reconnect_needed} = 0;
    }
}

# Метод сохраняет ошибку соединения с брокером сообщений в базу.
# Реализован таймаут, чтобы не спамить их слишком часто в случае разрыва соединения.
sub save_broker_conn_error {
    my $self = shift;
    my $interval = 3 * 60; # интервал
    # Время последнего сохранения
    my $last_save = $self->{last_save_broker_conn_error};
    # Если нет времени последнего сохранения или таймаут прошёл
    if (!defined($last_save) || time() - $last_save > $interval) {
        # Сохранить ошибку
        $self->save_error(ERR_BROKER_CONNECTION);
        # Установить время последнего сохранения
        $self->{last_save_broker_conn_error} = time();
    }
}

# Метод реализует главный цикл обработки сообщений.
sub process_loop {
    my $self = shift;
    my $done = shift; # ссылка на переменную-флаг для остановки цикла.
    # Цикл, пока не активна переменная done
    while (!$$done) {
        eval {
            # Обработать один фрейм от брокера
            my $r = $self->process_step(1);
            # Если возникла ошибка
            if ($r->{Result} ne '0') {
                # Залогировать предупреждение
                $self->log("warning", "process_loop: process_step error: " . $r->{ErrMsg});
            }
            # Очистить префикс логирования, который мог быть до этого изменён
            $self->{log_prefix} = undef;
        };
        # Если возникла ошибка
        if (my $err = $@) {
            # Залогировать ошибку
            $self->log("error", "process_loop: process_step died: " . $err);
            # Сохранить ошибку
            $self->save_error(ERR_PROCESSING);
            # Очистить префикс слогирования
            $self->{log_prefix} = undef;
            # Вызвать метод восстановления
            $self->recover;
            # Пауза
            sleep(3);
        }
    }
}

# Метод получает и обрабатывает один фрейм от брокера
sub process_step {
    my $self = shift;
    # Параметр таймаута
    my $timeout = shift;
    # Очистить префикс логирования
    $self->{log_prefix} = undef;

    # Проверить / восстановить соединения с базой и брокером при необходимости
    $self->check_database_connection();
    $self->check_broker_connection();

    # Получить следующее сообщение
    my $r = $self->{broker}->recv_frame($timeout);
    # Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Broker recv_frame error: ' . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_BROKER_RECV);
        # Установить флаг необходимости реконнекта брокера
        $self->{broker_reconnect_needed} = 1;
        # Вернуть результат
        return $r;
    }
    # Получить фрейм из результата
    my $frame = $r->{Frame};
    # Если не получен фрейм
    unless (defined $frame) {
        # Вернуть результат, что фрейм не получен
        return {Result => 0, ErrCode => 0, ErrMsg => 'No frame received'};
    }
    # Если фрейм не содержит сообщение
    if ($frame->command ne 'MESSAGE') {
        # Залогировать ошибку
        $self->log('error', 'Skipping frame, not a MESSAGE: ' . $r->{Frame}->command);
        # Сохранить ошибку
        $self->save_error(ERR_BROKER_RECV);
        # Установить флаг необходимости реконнекта брокера
        $self->{broker_reconnect_needed} = 1;
        # Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Skipped (bad frame type)'};
    }

    # Обновить таймер простоя брокера без новых сообщений
    $self->{broker_idle_timer} = time();

    # Получить информационные заголовки из сообщения
    # Они позволят ответить ошибкой, если произошла проблема получения, парсинга или валидации документа
    # Ид отправителя
    my $info_sender_id = $frame->headers->{sender_id};
    # Ид документа
    my $info_doc_id = $frame->headers->{doc_id};
    # Тип документа
    my $info_doc_type = $frame->headers->{doc_type};
    # Ид получателя
    my $info_receiver_id = $self->{db}->get_receiver_code($info_doc_id, $info_sender_id);
    # Установить префикс логирования
    $self->{log_prefix} = "[$info_sender_id-$info_doc_id] ";
    # Получить таймстамп высокого разрешения
    my $timestamp = timestamp_hires();
    # Залогировать сервисную информацию
    $self->log('info', "In: Timestamp=$timestamp; Frame headers: ".remove_crlf(dumper($frame->headers)));

    # Определить, от кого сообщение попало в очередь
    my $msg_source = $frame->headers->{source};
    # Если источник это система и в фрейме определено поле real_source
    if ($msg_source eq $self->{config}->{sys_id} && defined $frame->headers->{real_source}) {
        # Назначить источник из поля real_source
        $msg_source = $frame->headers->{real_source};
    }
    # Получить ip-адрес источника
    my $msg_source_ip = $frame->headers->{'source-ip'};
    # Тело сообщения, файл сообщения, длина
    my ($msg_body, $msg_file, $msg_len);

    # Тело сообщения лежит или в отдельном файле директории spool брокера, или находится в теле
    # фрейма. Это можно определить по заголовку "file_id".
    my $file_id = $frame->headers->{file_id};
    # Если ид файла не пустой
    if (defined $file_id && $file_id =~ /\S+/) {
        # Получить папку хранилища брокера
        my $broker_spool_dir = $self->{config}->{broker_spool_dir};
        # Удалить в имени папки последний "/"
        $broker_spool_dir =~ s|\/$||;
        # Составить имя файла из папки, ид и .blob
        my $input_file = $broker_spool_dir . '/' . $msg_source . '-' . $file_id . '.blob';
        # Залогировать сервисную информацию
        $self->log('info', "Input file: $input_file");
        # Если файл не существует
        unless (-f $input_file) {
            # Залогировать предупреждение
            $self->log('warning', "Input file does not exist: ($input_file)");
            # Сохранить ошибку
            $self->save_error(ERR_INPUT_FILE_NOT_FOUND, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
            # Отправить ответы на ошибку документа
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_INPUT_FILE_NOT_FOUND, CyberFT::Errors::desc(ERR_INPUT_FILE_NOT_FOUND),
            );
            # Послать ACK брокеру
            $self->{broker}->send_ack($frame);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Input file does not exist"};
        }

        # Проверить, не превышен ли максимальный размер XML-конверта.
        $msg_len = -s $input_file;
        # Если превышен
        if ($msg_len > $self->{config}->{envelope_max_size}) {
            # Залогировать предупреждение
            $self->log('warning', "Maximum envelope size exceeded: $msg_len");
            # Сохранить ошибку
            $self->save_error(ERR_MAX_ENVELOPE_SIZE, $info_doc_id, $msg_len, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
            # Отправить ответы на ошибку документа
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_MAX_ENVELOPE_SIZE, CyberFT::Errors::desc(ERR_MAX_ENVELOPE_SIZE),
            );
            # Послать ACK брокеру
            $self->{broker}->send_ack($frame);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Maximum envelope size exceeded"};
        }

        # Если документ слишком большой, переместить его во временный файл.
        if ($msg_len > $MAX_IN_MEMORY_DOC_SIZE) {
            # Создать путь для временного файла
            $msg_file = temp_filename($self->{config}->{temp_dir}, "router");
            # Залогировать сервисную информацию
            $self->log('info', "Moving document to: $msg_file");
            # Если перемещение входного файла во временный файл было неуспешным
            unless (File::Copy::move($input_file, $msg_file)) {
                # Залогировать ошибку
                $self->log('error', "Input file move error: ($input_file, $msg_file): $!");
                # Сохранить ошибку
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
                # Отправить ответы на ошибку документа
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
                # Послать ACK брокеру
                $self->{broker}->send_ack($frame);
                # Вернуть результат с ошибкой
                return {Result => 1, ErrCode => 10, ErrMsg => "Input file move error"};
            }
        } else {
            eval {
                # Прочитать файл в тело сообщения
                read_file($input_file, \$msg_body);
                # Удалить файл
                unlink($input_file);
            };
            # Если возникла ошибка
            if (my $err = $@) {
                # Залогировать ошибку
                $self->log('error', "Input file read error: $err");
                # Сохранить ошибку
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
                # Отправить ответы на ошибку документа
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
                # послать ACK брокеру
                $self->{broker}->send_ack($frame);
                # Вернуть результат с ошибкой
                return {Result => 1, ErrCode => 10, ErrMsg => "Input file read error"};
            }
        }
    } else {
        # Проверить, не превышен ли максимальный размер XML-конверта.
        $msg_len = length($frame->body);
        if ($msg_len > $self->{config}->{envelope_max_size}) {
            # Залогировать предупреждение
            $self->log('warning', "Maximum envelope size exceeded: $msg_len");
            # Сохранить ошибку
            $self->save_error(ERR_MAX_ENVELOPE_SIZE, $info_doc_id, $msg_len, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
            # Отправить ответы на ошибку документа
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_MAX_ENVELOPE_SIZE, CyberFT::Errors::desc(ERR_MAX_ENVELOPE_SIZE),
            );
            # Послать ACK брокеру
            $self->{broker}->send_ack($frame);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Maximum envelope size exceeded"};
        }

        # Если документ слишком большой, то поместить тело сообщения во временный файл
        if ($msg_len > $MAX_IN_MEMORY_DOC_SIZE) {
            # Создать путь для временного файла
            $msg_file = temp_filename($self->{config}->{temp_dir}, "router");
            # Залогировать сервисную информацию
            $self->log('info', "Saving document to: $msg_file");
            # Записать тело фрейма во временный файл
            eval {
                write_file($msg_file, \$frame->body);
            };
            # Если возникла ошибка
            if (my $err = $@) {
                # Залогировать ошибку
                $self->log('error', "Input file write error: $msg_file: $err");
                # Сохранить ошибку
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
                # Отправить ответы на ошибку документа
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
                # Послать ACK брокеру
                $self->{broker}->send_ack($frame);
                # Вернуть результат с ошибкой
                return {Result => 1, ErrCode => 10, ErrMsg => "Input file read error"};
            }
        } else {
            # Заполнить тело сообщения из тела фрейма
            $msg_body = $frame->body;
        }
    }
    # Флаг, который определяет, находится ли сообщение в памяти
    my $inmemory = (defined $msg_body) ? 1 : 0;
    # Залогировать сервисную информацию
    $self->log('info', "Document size: $msg_len; In-memory processing: $inmemory");

    # На этом этапе должна быть определена только одна из переменных: msg_body или msg_file,
    # в зависимости от размера обрабатываемого документа

    # Обработать сообщение
    $self->process_message(
        msg_body         => $msg_body,
        msg_file         => $msg_file,
        msg_len          => $msg_len,
        msg_source       => $msg_source,
        msg_source_ip    => $msg_source_ip,
        info_sender_id   => $info_sender_id,
        info_doc_id      => $info_doc_id,
        info_doc_type    => $info_doc_type,
        info_receiver_id => $info_receiver_id
    );

    # Если существует временный файл
    if (defined $msg_file && -f $msg_file) {
        # Удалить временный файл
        unlink($msg_file);
    }

    # Перейти к следующему сообщению
    # Послать ACK брокеру
    my $r = $self->{broker}->send_ack($frame);
	# Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Broker send_ack error: ' . $r->{ErrMsg});
        # Установить флаг необходимости реконнекта брокера
        $self->{broker_reconnect_needed} = 1;
        return $r;
    }
    # Вернуть результат с успехом
    return {Result => 0, ErrCode => 0, ErrMsg => 'OK'};
}

# Метод обрабатывает отдельное сообщение (xml-конверт)
sub process_message {
    my ($self, %opts) = @_;
    # Получить входные параметры
    my $msg_body         = $opts{msg_body};
    my $msg_file         = $opts{msg_file};
    my $msg_len          = $opts{msg_len};
    my $msg_source       = $opts{msg_source};
    my $msg_source_ip    = $opts{msg_source_ip};
    my $info_sender_id   = $opts{info_sender_id};
    my $info_doc_id      = $opts{info_doc_id};
    my $info_doc_type    = $opts{info_doc_type};
    my $info_receiver_id = $opts{info_receiver_id};

    # Распарсить сообщение
    my $r = CyberFT::Envelope::parse(xml_string => $msg_body, xml_file => $msg_file);
    # Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать предупреждение
        $self->log('warning', "Envelope parse error ($info_doc_id): " . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_ENVELOPE_PARSE, $info_doc_id, $r->{ErrMsg}, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
        # Отправить ответы на ошибку документа
        $self->reply_doc_error(
            $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
            ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE),
        );
        # Сохранить временный файл для отладки
        $self->debug_save_tmp_doc($msg_body, $msg_file);
        # Вернуться
        return;
    }

    # Получить из результата парсинга конверт
    my $envelope = $r->{Envelope};
    # Получить из конверта поля документа
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
    my $trace_list = $envelope->{TraceList};
    # Залогировать сервисную информацию
    $self->log('info', 'Parsed envelope: ' . remove_crlf(dumper($envelope)));
    # Установить префикс логирования
    $self->{log_prefix} = "[$sender_id-$doc_id] ";

    # Сразу сформировать ACK для предыдущего узла, о том, что его сообщение получено
    $self->send_ack($msg_source, $envelope);

    # Если при дальнейшей обработке возникнет ошибка, документ все же нужно будет
    # сохранить, но с информацией об ошибке
    my $is_error = 0; # флаг ошибки
    my ($error_code, $error_desc); # код и описание ошибки

    # Привести DocDate к серверному часовому поясу и к нужному формату.
    my $doc_date; # дата документа
    # Если не было ошибки
    unless ($is_error) {
        # Дата документа из конверта
        my $env_doc_date = $envelope->{DocDate};
        # Сконвертированная дата
        my ($dt, $err) = $self->convert_datetime($env_doc_date);
        # Если возникла ошибка
        if (defined $err) {
            # Залогировать предупреждение
            $self->log('warning', "DocDate error ($env_doc_date): " . $err);
            # Сохранить ошибку
            $self->save_error(ERR_ENVELOPE_PARSE, $doc_id, "Invalid DocDate", undef, $sender_id, $info_receiver_id, $info_doc_type);
            # Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE));
            # Установить флаг ошибки, код и описание ошибки
            $is_error = 1;
            $error_code = ERR_ENVELOPE_PARSE;
            $error_desc = CyberFT::Errors::desc(ERR_ENVELOPE_PARSE);
        } else {
            # Изменить дату документа на сконвертированную
            $doc_date = $dt;
            # Залогировать сервисную информацию
            $self->log('info', "Converted DocDate: '$env_doc_date' -> '$doc_date'");
        }
    }

    # Проверка подписей
    my ($sig_type, $signatures);
    # Если не было ошибки
    unless ($is_error) {
        # Тип подписи Origin, если трейслист пустой, иначе Trace
        $sig_type = @$trace_list > 0 ? 'Trace' : 'Origin';
        # Если для данного типа документа и подписи нет проверок
        if ($self->skip_signature_validation($doc_type, $sig_type)) {
            # Залогировать сервисную информацию
            $self->log('info', 'Signature validation is skipped');
            # Очистить список подписей
            $signatures = [];
        } else {
            # Проверить подписи
            my $r = $self->check_signatures($envelope, $msg_source, $msg_body, $msg_file);
            # Если результат успешный
            if ($r->{Result} eq '0') {
                # Тип подписи взять из результата
                $sig_type = $r->{Type};
                # Список подписей взять из результата
                $signatures = $r->{CheckedSignatures};
                # Получить список всех фингерпринтов из списка подписей
                my $fingerprints_str = join(',', map {$_->{fingerprint}} @$signatures);
                # Залогировать сервисную информацию
                $self->log('info', "Checked signatures (Type=$sig_type) Certificate fingerprints: $fingerprints_str");
            } else {
                # Залогировать предупреждение
                $self->log('warning', "Signature check error: " . $r->{ErrMsg});
                # Послать статус-репорт
                $self->send_status_report($envelope, 'RJCT', ERR_SIGNATURE_CHECK, CyberFT::Errors::desc(ERR_SIGNATURE_CHECK));
                # Установить флаг ошибки, код и описание ошибки
                $is_error = 1;
                $error_code = ERR_SIGNATURE_CHECK;
                $error_desc = CyberFT::Errors::desc(ERR_SIGNATURE_CHECK);
            }
        }
    }

    # Обработка технических типов документов, которые не нужно сохранять в базу данных
    if ($doc_type =~ /^(CFTAck|CFTChkAck|CFTResend)$/) {
        # Если не было ошибки
        unless ($is_error) {
            # Обработать техническое сообщение
            $self->process_tech_message($envelope, $msg_source);
        }
        return;
    }

    # Если в конверте есть информация о платежах, нужно ее тоже достать и провалидировать
    my ($msg_cnt, $msg_cur, $msg_sum);
    unless ($is_error) {
        my $r = $self->validate_pay_info($envelope);
        # Если возникла ошибка
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', "PaymentRegisterInfo validation error: " . $r->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_VALIDATE_PAYREGINFO, $doc_id, undef, undef, $sender_id, $info_receiver_id, $info_doc_type);
            # Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', ERR_VALIDATE_PAYREGINFO, CyberFT::Errors::desc(ERR_VALIDATE_PAYREGINFO));
            # Установить флаг ошибки, код и описание ошибки
            $is_error = 1;
            $error_code = ERR_VALIDATE_PAYREGINFO;
            $error_desc = CyberFT::Errors::desc(ERR_VALIDATE_PAYREGINFO);
        } else {
            # Получить количество платежей, сумму и валюту из конверта
            $msg_cnt = $envelope->{PayInfo_count};
            $msg_cur = $envelope->{PayInfo_cur};
            $msg_sum = $envelope->{PayInfo_sum};
        }
    }

    # Если в конверте есть параметр ValidUntil, привести его к серверному часовому поясу и к нужному формату
    my $time_limit;
    unless ($is_error) {
        # Получить параметр
        my $valid_until = $envelope->{ValidUntil};
        # Если он есть
        if (defined $valid_until) {
            # Сконвертировать дату и время
            my ($dt, $err) = $self->convert_datetime($valid_until);
            # Если возникла ошибка
            if (defined $err) {
                # Залогировать предупреждение
                $self->log('warning', "TimeLimit error ($valid_until): " . $err);
                # Сохранить ошибку
                $self->save_error(ERR_VALIDATE_VALIDUNTIL, $doc_id, $valid_until, undef, $sender_id, $info_receiver_id, $info_doc_type);
                # Послать статус-репорт
                $self->send_status_report($envelope, 'RJCT', ERR_VALIDATE_VALIDUNTIL, CyberFT::Errors::desc(ERR_VALIDATE_VALIDUNTIL));
                # Установить флаг ошибки, код и описание ошибки
                $is_error = 1;
                $error_code = ERR_VALIDATE_VALIDUNTIL;
                $error_desc = CyberFT::Errors::desc(ERR_VALIDATE_VALIDUNTIL);
            } else {
                $time_limit = $dt;
                # Залогировать сервисную информацию
                $self->log('info', "Converted TimeLimit: '$valid_until' -> '$time_limit'");
            }
        }
    }

    # Перед добавлением в базу документ нужно подписать в разделе TraceList
    unless ($is_error) {
        my $r = CyberFT::Envelope::inject_trace_sign(
            xml_string       => $msg_body,
            xml_file         => $msg_file,
            signer_id        => $self->{config}->{sys_id},
            sender_id        => $msg_source,
            sender_ip        => $msg_source_ip,
            receiver_id      => '',
            receiver_ip      => '',
            cert_subject     => $self->{sys_cert_subject},
            cert_fingerprint => $self->{sys_cert_fingerprint},
            cert_file        => $self->{config}->{sys_certificate_file},
            pkey_file        => $self->{config}->{sys_private_key_file},
            pkey_pwd         => $self->{config}->{sys_private_key_password},
        );
        # Если возникла ошибка
        if ($r->{Result} ne '0') {
            # Залогировать ошибку
            $self->log('error', "Envelope TraceList sign error: " . $r->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_INJECT, $doc_id, undef, undef, $sender_id, $info_receiver_id, $info_doc_type);
            # Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', ERR_SIGNATURE_INJECT, CyberFT::Errors::desc(ERR_SIGNATURE_INJECT));
            # Сохранить отладочный временный файл
            $self->debug_save_tmp_doc($msg_body, $msg_file);
            # Установить флаг ошибки, код и описание ошибки
            $is_error = 1;
            $error_code = ERR_SIGNATURE_INJECT;
            $error_desc = CyberFT::Errors::desc(ERR_SIGNATURE_INJECT);
        } else {
            # Залогировать сервисную информацию
            $self->log('info', 'Signed TraceList');
            # Если в результате вернулось тело сообщения
            if (defined $msg_body) {
                # Получить тело сообщения из результата
                $msg_body = $r->{XML};
            }
        }
    }

    # Добавить сообщение в базу
    my $r = $self->save_message_to_db(
        doc_id      => $doc_id,
        doc_type    => $doc_type,
        doc_time    => $doc_date,
        sender_id   => $sender_id,
        receiver_id => $receiver_id,
        msg         => $msg_body,
        msg_file    => $msg_file,
        msg_len     => $msg_len,
        msg_sum     => $msg_sum,
        msg_cnt     => $msg_cnt,
        msg_cur     => $msg_cur,
        time_limit  => $time_limit,
        is_error    => $is_error,
        error_code  => $error_code,
        error_desc  => $error_desc,
    );
    # Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать предупреждение
        $self->log('warning', "Adding message error: " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_SAVE_MESSAGE, $doc_id, $r->{ErrMsgDB}, undef, $sender_id, $info_receiver_id, $info_doc_type);
        # Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', $r->{ErrCode}, $r->{ErrMsg});
        return;
    }
    # Залогировать сервисную информацию
    $self->log('info', "Successfully added to the database; is_error=$is_error");
    # Получить ид сообщения из результата
    my $message_id = $r->{Message};
    # Получить признак локального получателя
    my $receiver_is_local = ($r->{AnotherSegment} eq '0');

    # Если сообщение пришло не от другого процессинга,
    # прикрепить к сообщению все сертификаты, которыми оно подписано
    if (!$is_error && $sig_type eq 'Origin') {
        $self->link_message_signatures(
            envelope   => $envelope,
            message_id => $message_id,
            signatures => $signatures,
        );
    }

    # Если это StatusReport, который предназначается локальному терминалу, то нужно
    # выставить статус исходного документа в базе.
    if (!$is_error && $doc_type =~ /^CFTStatusReport$/i && $receiver_is_local) {
        $self->update_doc_status_by_status_report($envelope);
    }
}

# Метод определяет, надо ли пропускать проверку подписей
sub skip_signature_validation {
    my ($self, $doc_type, $signature_type) = @_;
    # Вернуть результат по совпадению типов
    return $signature_type eq 'Origin' && $doc_type =~ m/^(CFTStatusReport|CFTResend|CFTAck|CFTChkAck)$/;
}

# Метод обрабатывает техническое сообщение
sub process_tech_message {
    # Входные параметры
    my ($self, $envelope, $msg_source) = @_;
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
    # Если ид получателя не равен ид системы
    if ($receiver_id ne $self->{config}->{sys_id}) {
        # Залогировать предупреждение
        $self->log('warning', "Ignored $doc_type: bad receiver: $receiver_id");
        # Вернуться
        return;
    }

    # DocType = CFTAck
    if ($doc_type eq 'CFTAck') {
        # Поменять статус соответствующего сообщения в базе на "Доставлено следующему узлу"
        my $ref_doc_id = $envelope->{Ack_RefDocId};
        my $ref_sender_id = $envelope->{Ack_RefSenderId};
        my $new_status = 15;
        # Сохранить статус сообщения в базе данных
        my $r = $self->save_message_status_to_db(doc_id => $ref_doc_id, sender_id => $ref_sender_id, status => $new_status, doc_type => $doc_type);
        # Если возникла ошибка
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', "Saving ack error: ($ref_doc_id, $ref_sender_id, $new_status): " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$ref_sender_id-$ref_doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        } else {
            # Залогировать сервисную информацию
            $self->log('info', "Saved ack: RefDocId=" . $ref_doc_id . " RefSenderId=" . $ref_sender_id);
        }
        # Вернуться
        return;
    }

    # DocType = CFTChkAck
    if ($doc_type eq 'CFTChkAck') {
        # Проверить наличие соответствующего документа в базе
        # В ответ отправить CFTAck или CFTResend
        my $ref_doc_id = $envelope->{ChkAck_RefDocId};
        my $ref_sender_id = $envelope->{ChkAck_RefSenderId};
        # Конверт связанного сообщения
        my $ref_envelope = {
            DocId    => $ref_doc_id,
            SenderId => $ref_sender_id,
            DocType  => "",
        };
        # Проверить, что документ существует в базе
        my $exists = $self->check_if_doc_exists_in_db(sender_id => $ref_sender_id, doc_id => $ref_doc_id);
        # Если существует
        if ($exists) {
            # Залогировать сервисную информацию
            $self->log('info', "Checked document: Exists: RefDocId=$ref_doc_id, RefSenderId=$ref_sender_id");
            # Послать ACK
            $self->send_ack($msg_source, $ref_envelope);
        } else {
            # Залогировать сервисную информацию
            $self->log('info', "Checked document: Not exists: RefDocId=$ref_doc_id, RefSenderId=$ref_sender_id");
            # Отправить запрос на переотправку сообщения
            $self->send_resend($msg_source, $ref_envelope);
        }
        # Вернуться
        return;
    }

    # DocType = CFTResend
    if ($doc_type eq 'CFTResend') {
        # Поменять статус соответствующего документа на переотправку.
        my $ref_doc_id = $envelope->{Resend_RefDocId};
        my $ref_sender_id = $envelope->{Resend_RefSenderId};
        # Сохранить статус сообщения в базе данных
        my $r = $self->save_message_status_resend_to_db(doc_id => $ref_doc_id, sender_id => $ref_sender_id, doc_type => $doc_type);
        # Если возникла ошибка
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', "Saving resend status error: ($ref_doc_id, $ref_sender_id): " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$ref_sender_id-$ref_doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        } else {
            # Залогировать сервисную информацию
            $self->log('info', "Saved resend status: RefDocId=" . $ref_doc_id . " RefSenderId=" . $ref_sender_id);
        }
        # Вернуться
        return;
    }
}

# Метод изменяет статус исходного документа на основе обрабатываемого StatusReport
sub update_doc_status_by_status_report {
    # Входные параметры конверта
    my ($self, $envelope) = @_;
    # Получить поля документа из конверта
    my $doc_id = $envelope->{DocId};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
    my $ref_doc_id = $envelope->{StatusReport_RefDocId};
    my $status_code = $envelope->{StatusReport_StatusCode};
    my $doc_type = $envelope->{DocType};
    # Если есть связанное сообщение и статус RJCT или ACDC
    if ($ref_doc_id =~ /\S+/ && $status_code =~ /^(RJCT|ACDC)$/) {
        # Новый статус, флаг ошибки, код ошибки, описание ошибки
        my ($new_status, $is_error, $error_code, $error_desc);
        # Если статус RJCT
        if ($status_code eq 'RJCT') {
            $new_status = 18; # Доставлен получателю с ошибкой
            # Установить флаг ошибки, код и описание ошибки
            $is_error = 1;
            $error_code = $envelope->{StatusReport_ErrorCode};
            $error_desc = $envelope->{StatusReport_ErrorDescription};
        } else {
            $new_status = 17; # Доставлен получателю
            # Очистить флаг ошибки
            $is_error = 0;
        }
        # Сохранить статус сообщения в базе данных
        my $r = $self->save_message_status_to_db(
            doc_id     => $ref_doc_id,
            sender_id  => $receiver_id,
            status     => $new_status,
            is_error   => $is_error,
            error_code => $error_code,
            error_desc => $error_desc,
            doc_type   => $doc_type,
        );
        # Если результат содержит ошибку
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', "Saving status report error: ($ref_doc_id, $receiver_id, $new_status, $is_error, $error_code, $error_desc): " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$receiver_id-$ref_doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        } else {
            # Если установлен флаг ошибки
            if ($is_error) {
                # Найти связанное сообщение
                my $ref_message = $self->{db}->get_message_info($envelope->{StatusReport_RefDocId}, $receiver_id);
                # Если найдено
                if ($ref_message) {
                    # Сохранить ошибку
                    $self->save_error(
                        ERR_RECIPIENT_REJECTION,
                        $error_code,
                        $error_desc,
                        undef,
                        $ref_message->{sender},
                        $ref_message->{receiver},
                        $ref_message->{doc_type}
                    );
                } else {
                    # Залогировать предупреждение
                    $self->log('warning', "Cannot find reference message $envelope->{StatusReport_RefDocId} while logging reject status report");
                }
            }
            # Залогировать сервисную информацию
            $self->log('info', "Saved status report: RefDocId=$ref_doc_id StatusCode=$status_code ErrorCode=$error_code ErrorDescription=$error_desc");
        }
    } else {
        # Залогировать сервисную информацию
        $self->log('info', "Ignored status report: RefDocId=$ref_doc_id StatusCode=$status_code");
    }
}

# Метод отправляет Ack-сообщение предыдущему узлу
sub send_ack {
    # Получить входные параметры
    my ($self, $msg_source, $envelope) = @_;
    # Получить поля заголовка из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
    # Если документ сервисного типа, вернуться
    if ($doc_type =~ /^(CFTAck|CFTChkAck|CFTResend)$/) {
        return;
    }
    # Сгенерировать документ типа ACK
    my ($ack, $ack_id) = $self->gen_ack($msg_source, $doc_id, $sender_id);
    # Если результат пустой, вернуться
    unless (defined $ack) {
        return;
    }
    # Послать документ брокеру
    my $r = $self->{broker}->send_frame(
        $msg_source,
        $ack,
        {
            'doc_id' => $ack_id,
            'sender_id' => $self->{config}->{sys_id},
            'doc_type' => 'CFTAck',
            'ref_doc_id' => $doc_id,
        },
    );
    # Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'send_ack: Broker send_frame error: ' . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_SEND_ACK, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
    }
    # Залогировать сервисную информацию
    $self->log('info', "Sent: Ack to $msg_source (RefSenderId=$sender_id, RefDocId=$doc_id) DocId=$ack_id");
}

# Создание подписанного отчета о получении сообщения для узла, от которого получено сообщение (Ack).
sub gen_ack {
    my $self = shift;
    # Получить входные параметры
    my $to = shift;
    my $doc_id = shift;
    my $sender_id = shift;
    # Строка XML
    my $report_xml = '';
    $report_xml .= q{<Ack xmlns="http://cyberft.ru/xsd/cftdata.01">};
    $report_xml .= q{<RefDocId>} . $doc_id . q{</RefDocId>};
    $report_xml .= q{<RefSenderId>} . $sender_id . q{</RefSenderId>};
    $report_xml .= q{</Ack>};

    # Поместить отчёт в стандартный xml-конверт CyberFT
    my $r = CyberFT::Envelope::create_signed(
        doc_type         => 'CFTAck',
        sender_id        => $self->{config}->{sys_id},
        receiver_id      => $to,
        body_mime        => 'application/xml',
        body             => $report_xml,
        cert_subject     => $self->{sys_cert_subject},
        cert_fingerprint => $self->{sys_cert_fingerprint},
        cert_file        => $self->{config}->{sys_certificate_file},
        pkey_file        => $self->{config}->{sys_private_key_file},
        pkey_pwd         => $self->{config}->{sys_private_key_password},
    );

    # Если возникла ошибка
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'gen_ack: CyberFT::Envelope::create error: ' . $r->{ErrMsg});
        # Вернуть неопределённый результат
        return undef;
    }
    # Вернуть контент и ид документа
    return ($r->{Content}, $r->{DocId});
}

# Метод отправляет запрос CFTResend предыдущему узлу.
sub send_resend {
    # Получить входные параметры
    my ($self, $msg_source, $envelope) = @_;
    # Получить поля документа из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
    # Сгенерировать документ типа resend
    my ($resend, $resend_id) = $self->gen_resend($msg_source, $doc_id, $sender_id);
    # Если пустой результат, вернуться
    unless (defined $resend) {
        return;
    }
    # Послать документ брокеру
    my $r = $self->{broker}->send_frame(
        $msg_source,
        $resend,
        {
            'doc_id' => $resend_id,
            'sender_id' => $self->{config}->{sys_id},
            'doc_type' => 'CFTResend',
            'ref_doc_id' => $doc_id,
        },
    );
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'send_resend: Broker send_frame error: ' . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_SEND_ACK, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
    }
    # Залогировать сервисную информацию
    $self->log('info', "Sent: CFTResend to $msg_source (RefSenderId=$sender_id, RefDocId=$doc_id) DocId=$resend_id");
}

# Метод создаёт подписанный документ CFTResend
sub gen_resend {
    my $self = shift;
    # Получить входные параметры
    my $to = shift;
    my $doc_id = shift;
    my $sender_id = shift;

    # Строка XML
    my $report_xml = '';
    $report_xml .= q{<Resend xmlns="http://cyberft.ru/xsd/cftdata.01">};
    $report_xml .= q{<RefDocId>} . $doc_id . q{</RefDocId>};
    $report_xml .= q{<RefSenderId>} . $sender_id . q{</RefSenderId>};
    $report_xml .= q{</Resend>};

    # Поместить отчёт в стандартный конверт CyberFT
    my $r = CyberFT::Envelope::create_signed(
        doc_type         => 'CFTResend',
        sender_id        => $self->{config}->{sys_id},
        receiver_id      => $to,
        body_mime        => 'application/xml',
        body             => $report_xml,
        cert_subject     => $self->{sys_cert_subject},
        cert_fingerprint => $self->{sys_cert_fingerprint},
        cert_file        => $self->{config}->{sys_certificate_file},
        pkey_file        => $self->{config}->{sys_private_key_file},
        pkey_pwd         => $self->{config}->{sys_private_key_password},
    );
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'gen_resend: CyberFT::Envelope::create error: ' . $r->{ErrMsg});
        return undef;
    }
    # Вернуть контент и ид документа
    return ($r->{Content}, $r->{DocId});
}

# Метод посылает ответный StatusReport на входящий документ
sub send_status_report {
    # Получить входные параметры
    my ($self, $envelope, $status_code, $err_code, $err_msg) = @_;
    # Получить поля заголовка из конверта
    my $sender_id = $envelope->{SenderId};
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $receiver_id = $envelope->{ReceiverId};
    # Если документ сервисного типа, вернуться
    if ($doc_type =~ /^(CFTAck|CFTStatusReport|CFTChkAck|CFTResend)$/) {
        return;
    }
    # Сгенерировать статус-репорт
    my ($rep, $rep_id, $rep_docdate) = $self->gen_status_report(
        $sender_id,
        $doc_id,
        $status_code,
        $err_code,
        $err_msg
    );
    # В случае пустого результата вернуться
    unless (defined $rep) {
        return;
    }
    # Добавить ответ в базу
    my $r = $self->save_message_to_db(
        doc_id      => $rep_id,
        doc_type    => 'CFTStatusReport',
        doc_time    => $rep_docdate,
        sender_id   => $self->{config}->{sys_id},
        receiver_id => $sender_id,
        msg         => $rep,
        msg_len     => length($rep),
    );
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать предупреждение
        $self->log('warning', "send_status_report: save_message_to_db error: " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
        # Сохранить ошибку
        $self->save_error(ERR_SAVE_STATUS_REPORT, $doc_id, $r->{ErrMsgDB}, undef, $sender_id, $receiver_id, $doc_type);
        return;
    }
    # Залогировать сервисную информацию
    $self->log('info', "Sent: StatusReport to $sender_id (RefDocId=$doc_id, StatusCode=$status_code) DocId=$rep_id");
}

# Метод создаёт подписанный отчет об ошибке обработки сообщения для отправителя (StatusReport)
sub gen_status_report {
    my $self = shift;
    # Входные параметры
    my $to = shift;
    my $doc_id = shift;
    my $status_code = shift;
    my $error_code = shift;
    my $error_message = shift;
    # Экранирование спецсимволов в сообщении об ошибке
    $error_message =~ s/&/&amp;/g;
    $error_message =~ s/</&lt;/g;
    $error_message =~ s/>/&gt;/g;

    # Строка XML
    my $report_xml = '';
    $report_xml .= q{<StatusReport xmlns="http://cyberft.ru/xsd/cftdata.01">};
    $report_xml .= q{<RefDocId>} . $doc_id . q{</RefDocId>};
    $report_xml .= q{<StatusCode>} . $status_code . q{</StatusCode>};
    $report_xml .= q{<ErrorCode>} . $error_code . q{</ErrorCode>};
    $report_xml .= q{<ErrorDescription>} . $error_message . q{</ErrorDescription>};
    $report_xml .= q{</StatusReport>};

    # Получение таймстампов
    my ($xml_date, $db_date) = gen_timestamps();

    # Поместить отчёт в стандартный конверт CyberFT
    my $r = CyberFT::Envelope::create_signed(
        doc_type         => 'CFTStatusReport',
        doc_date         => $xml_date,
        sender_id        => $self->{config}->{sys_id},
        receiver_id      => $to,
        body_mime        => 'application/xml',
        body             => $report_xml,
        cert_subject     => $self->{sys_cert_subject},
        cert_fingerprint => $self->{sys_cert_fingerprint},
        cert_file        => $self->{config}->{sys_certificate_file},
        pkey_file        => $self->{config}->{sys_private_key_file},
        pkey_pwd         => $self->{config}->{sys_private_key_password},
    );
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'gen_status_report: CyberFT::Envelope::create_signed error: ' . $r->{ErrMsg});
        # Сохранить ошибку в базе данных
        $self->save_error(ERR_PROCESSING);
        # Вернуть неопределённое значение
        return undef;
    }

    # Вернуть контент, ид документа, дату
    return ($r->{Content}, $r->{DocId}, $db_date);
}

# Метод отправляет Ack предыдущему узлу и StatusReport начальному отправителю
# в случае ошибки разбора сообщения
sub reply_doc_error {
    # Получить входные параметры
    my ($self, $msg_source, $info_sender_id, $info_doc_id, $info_doc_type, $err_code, $err_msg) = @_;
    # Все три параметра должны присутствовать в заголовках, иначе ничего не отправляем
    unless (defined $info_sender_id && defined $info_doc_id && defined $info_doc_type) {
        return;
    }
    # Создать конверт
    my $envelope = {
        SenderId => $info_sender_id,
        DocId    => $info_doc_id,
        DocType  => $info_doc_type,
    };
    # Послать ACK
    $self->send_ack($msg_source, $envelope);
    # Послать статус-репорт
    $self->send_status_report($envelope, 'RJCT', $err_code, $err_msg);
}

# Проверка корректности данных, которые приходят в тэге PaymentRegisterInfo xml-конверта.
sub validate_pay_info {
    my $self = shift;
    # Получить конверт из входного параметра
    my $envelope = shift;
    # Если конверт содержит платёжные данные
    if (defined $envelope->{PayInfo_sum} && $envelope->{PayInfo_sum} ne '') {
        # Нормализовать формат данных
        $envelope->{PayInfo_sum} =~ s/,/./;
        $envelope->{PayInfo_sum} =~ s/\.$//;
        # Если данные в неверном формате
        if ($envelope->{PayInfo_sum} !~ /^\d+\.?\d*$/) {
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 1, ErrMsg => "Payment info error: bad sum"};
        }
    }
    # Если конверт содержит количество платежей
    if (defined $envelope->{PayInfo_count} && $envelope->{PayInfo_count} ne '') {
        # Если формат числа неверный
        if ($envelope->{PayInfo_count} !~ /^\d*$/) {
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 2, ErrMsg => "Payment info error: bad count"};
        }
    }
    # Если конверт содержит валюту
    if (defined $envelope->{PayInfo_cur} && $envelope->{PayInfo_cur} ne '') {
        # Преобразовать валюту в верхний регистр
        $envelope->{PayInfo_cur} = uc($envelope->{PayInfo_cur});
        # Преобразовать название RUB в RUR
        $envelope->{PayInfo_cur} =~ s/^RUB$/RUR/;
    }
    # Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Приводим дату и время к серверному часовому поясу и к правильному формату для сохранения в базу.
sub convert_datetime {
    my $self = shift;
    # Получить дату из входного параметра
    my $datetime = shift;
    # Если не указана дата, вернуть ошибку
    if (!defined($datetime)) {
        return (undef, 'convert_datetime: datetime is not defined');
    }
    # Если дата в правильном формате 
    if ($datetime =~ /(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(Z|[+-]\d\d:\d\d)?/) {
        my $res;
        eval {
            # Разбить дату на части и поместить в список
            my @datetime = ($1, $2, $3, $4, $5, $6);
            my $term_tz = $7;

            my ($term_tz_h, $term_tz_m);
            # Если есть таймзона
            if ($term_tz =~ /^([+-])(\d\d):(\d\d)$/) {
                # Распарсить части таймзоны
                $term_tz_h = $1.$2;
                $term_tz_m = $1.$3;
            } else {
                # Создать нулевую таймзону
                $term_tz_h = 0;
                $term_tz_m = 0;
            }

            my ($serv_tz_h, $serv_tz_m);
            # Получить серверную таймзону
            if (strftime("%z", localtime) =~ /^([+-])(\d\d)(\d\d)$/) {
                # Если присутствует на сервере, распарсить по частям
                $serv_tz_h = $1.$2;
                $serv_tz_m = $1.$3;
            } else {
                # Создать нулевую таймзону
                $serv_tz_h = 0;
                $serv_tz_m = 0;
            }
            # Отнять от даты таймзону и добавить серверную
            @datetime = Date::Calc::Add_Delta_DHMS(@datetime, 0, -$term_tz_h, -$term_tz_m, 0);
            @datetime = Date::Calc::Add_Delta_DHMS(@datetime, 0, +$serv_tz_h, +$serv_tz_m, 0);
            # Свормировать новую строку даты
            $res = sprintf("%04d-%02d-%02d %02d:%02d:%02d", @datetime);
        };
        # Если возникла ошибка
        if (my $err = $@) {
            # Вернуть ошибку
            return (undef, "convert_datetime: $err");
        }
        # вернуть результат
        return ($res, undef);
    }
    # Вернуть ошибку
    return (undef, 'convert_datetime: invalid datetime format');
}

# Метод сохраняет сообщение в базу данных
sub save_message_to_db {
    my $self = shift;
    # Список входных параметров
    my %p = @_;

    my $hash;
    # Если указано тело сообщения
    if (defined $p{msg}) {
        # Вычислить хеш сообщения
        $hash = Digest::MD5::md5_hex($p{msg});
    } else {
        # Вычислить хеш файла
        $hash = md5_sum_file($p{msg_file});
    }
    # Параметры для сохранения
    my $params = {
        MsgBody          => $p{msg},
        MsgBody_FileName => $p{msg_file},
        SenderMsgCode    => $p{doc_id},
        SenderSwift      => $p{sender_id},
        ReceiverSwift    => $p{receiver_id},
        MsgCode          => $p{doc_type},
        MessageLength    => $p{msg_len},
        MessageSum       => $p{msg_sum},
        MessageCnt       => $p{msg_cnt},
        CurrCode         => $p{msg_cur},
        FormatCode       => 'xml',
        MsgHash          => $hash,
        Cmd              => 0,
        TimeLimit        => $p{time_limit},
        DocTime          => $p{doc_time},
        ExtIsError       => $p{is_error},
        ExtErrCode       => $p{error_code},
        ExtErrMsg        => $p{error_desc},
    };

    # Сделать запрос к базе
    my $result = $self->{db}->add_message($params);

    # Если результат содержит ошибку
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        # Если код ошибки 1 или 2
        if ($result->{Result} eq '1' || $result->{Result} eq '2') {
            # Присвоить код и описание ошибки из результата
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        } else {
            # Залогировать нестандартную ошибку
            $self->log('error', 'save_message_to_db: ' . $p{doc_id} .
                       ': add_message error: ' . $result->{ErrCode} . ': ' . $result->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_DATABASE, $p{doc_id}, $result->{ErrMsg}, undef, $p{sender_id}, $p{receiver_id}, $p{doc_type});
            # Установить код и описание ошибки
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            # Установаить флаг необходимости проверки базы данных
            $self->{db_check_needed} = 1;
        }
        # Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg, ErrMsgDB => $err_msg_db};
    }

    # Признак, что сообщение отправляется в другой сегмент сети
    my $another_segment = $result->{AnotherSegment};
    # Вернуть результат с успехом
    return {Result => 0, ErrCode => 0, ErrMsg => '', AnotherSegment => $another_segment, Message => $result->{Message}};
}

# Метод сохраняет статус сообщения в базу данных
# Расшифровка статусов:
#   15 - Доставлен следующему узлу
#   17 - Доставлен получателю
#   18 - Доставлен получателю с ошибкой
#   19 - Не доставлен
sub save_message_status_to_db {
    my $self = shift;
    # Список входных параметров
    my %p = @_;
    # Список параметров для сохранения
    my $params = {
        Message => 0,
        SenderSwift => $p{sender_id},
        ReceiverSwift => $p{receiver_id},
        SenderMsgCode => $p{doc_id},
        ExtIsError => defined($p{is_error}) ? $p{is_error} : 0,
        ExtErrCode => $p{error_code},
        ExtErrMsg => $p{error_desc},
        SendStatus => $p{status},
    };

    # Сделать запрос к базе
    my $result = $self->{db}->set_message_status($params);

    # Если результат содержит ошибку
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        # Если возвращаемое значение в результате равно 1
        if ($result->{Result} eq '1') {
            # Получить код и описание ошибки из результата
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        }
        else {
            # Залогировать нестандартную ошибку
            $self->log('error', 'save_message_status_to_db: ' . $p{doc_id} .
                       ': set_message_status error: ' . $result->{ErrCode} . ': ' . $result->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_DATABASE, $p{doc_id}, $result->{ErrMsg}, undef, $p{sender_id}, $p{receiver_id}, $p{doc_type});
            # Задать код и описание ошибки
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            # Установить флаг необходимости проверки базы данных
            $self->{db_check_needed} = 1;
        }
        # Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg, ErrMsgDB => $err_msg_db};
    }
    # Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Метод сохраняет статус сообщения "Переотправка" в базу данных
sub save_message_status_resend_to_db {
    my $self = shift;
    # Получить список входных параметров
    my %p = @_;
    # Параметры для сохранения
    my $params = {
        Message => 0,
        SenderSwift => $p{sender_id},
        ReceiverSwift => $p{receiver_id},
        SenderMsgCode => $p{doc_id},
    };

    # Сделать запрос к базе с параметрами
    my $result = $self->{db}->set_message_status_resend($params);

    # Если результат содержит ошибку
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        # Если возвращаемое значение в результате равно 1
        if ($result->{Result} eq '1') {
            # Получить код и описание ошибки из результата
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        }
        else {
            # Залогировать нестандартную ошибку
            $self->log('error', 'save_message_status_resend_to_db: ' . $p{doc_id} .
                       ': set_message_status_resend error: ' . $result->{ErrCode} . ': ' . $result->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_DATABASE, $p{doc_id}, $result->{ErrMsg}, undef, $p{sender_id}, $p{receiver_id}, $p{doc_type});
            # Задать код и описание ошибки
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            # Установить флаг необходимости проверки базы данных
            $self->{db_check_needed} = 1;
        }
        # Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg, ErrMsgDB => $err_msg_db};
    }
    # Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Метод проверяет подписи (новый вариант)
sub check_signatures {
    my $self = shift;
    # Параметр конверта
    my $envelope = shift;
    # Параметр источника сообщения
    my $msg_source = shift;
    # Параметр тела сообщения
    my $msg_body = shift;
    # Параметр файла сообщения
    my $msg_file = shift;
    # Получить подписи из конверта
    my $signatures = $envelope->{Signatures};
    # Получить трейслист из конверта
    my $trace_list = $envelope->{TraceList};
    # Получить ид отправителя из конверта
    my $sender_id = $envelope->{SenderId};
    # Получить ид документа из конверта
    my $doc_id = $envelope->{DocId};
    # Получить тип документа из конверта
    my $doc_type = $envelope->{DocType};
    # Получить тип получателя из конверта
    my $receiver_id = $envelope->{ReceiverId};
    # Тип подписи
    my $sig_type = undef;
    # Список проверенных подписей
    my $checked_signatures = [];

    # Если есть непустой TraceList, значит сообщение пришло от другого процессинга
    # Нужно взять последний трек и проверить в нём подпись
    if (scalar @$trace_list > 0) {
        $sig_type = 'Trace';
        # Получить последний трек
        my $trace = $trace_list->[scalar(@$trace_list) - 1];
        # Получить подписанта из трека
        my $signer = $trace->{SignerId};
        # Получить фингерпринт из трека
        my $fingerprint = $trace->{FingerPrint};
        # Получить путь к подписи из трека
        my $sigpath = $trace->{SignaturePath};
        # Если подписант не совпадает с источником сообщения
        if ($signer ne $msg_source) {
            # Залогировать предупреждение
            $self->log('warning', "check_signatures: Last TraceList record ($signer) doesn't correspond to message source ($msg_source)");
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Последняя запись в разделе TraceList ($signer) не соответствует заголовку source ($msg_source)", undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 6, ErrMsg => "Last TraceList record ($signer) doesn't correspond to message source ($msg_source)", Type => $sig_type};
        }
        # Получить сертификат по подписанту и фингерпринту
        my $r = $self->get_certificate($signer, $fingerprint);
        # Если результат содержит ошибку
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', 'check_signatures: Error getting certificate from database: ' . $signer . ", " . $fingerprint);
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Ошибка получения сертификата из базы данных: " . $signer . ", " . $fingerprint, undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {
                Result  => $r->{Result},
                ErrCode => $r->{ErrCode},
                ErrMsg  => $r->{ErrMsg},
                Type    => $sig_type
            };
        }
        # Получить сертификат и тип участника из результата
        my $cert = $r->{Certificate};
        my $member_type = $r->{MemberType};
        # Если тип участника не процессинг
        if ($member_type != 1) {
            # Залогировать предупреждение, что последняя запись в трейслисте не от процессинга
            $self->log('warning', 'check_signatures: Last TraceList record not from processing');
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Последняя запись в разделе TraceList добавлена не процессингом", undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 6, ErrMsg => 'Last TraceList record not from processing', Type => $sig_type};
        }
        # Верифицировать конверт
        my $r = CyberFT::Envelope::verify(
            xml_string => $msg_body,
            xml_file   => $msg_file,
            sigpath    => $sigpath,
            cert       => $cert,
        );
        # Если результат содержит ошибку
        if ($r->{Result} ne '0') {
            # Залогировать предупреждение
            $self->log('warning', 'check_signatures: Signature verify error: ' . $fingerprint);
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Подпись неверна: $fingerprint", undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {
                Result  => $r->{Result},
                ErrCode => $r->{ErrCode},
                ErrMsg  => $r->{ErrMsg},
                Type    => $sig_type
            };
        }
        # Добавить в список проверенных подписей фингерпринт и подписанта
        push @$checked_signatures, {fingerprint => $fingerprint, signer => $signer};
    } else {
        # Это сообщение пришло от обычного участника.
        $sig_type = 'Origin';
        # Если ид отправителя не равен источнику сообщения
        if ($sender_id ne $msg_source) {
            # Залогировать предупреждение
            $self->log('warning', "check_signatures: Envelope SenderId doesn't correspond to message source");
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Значение SenderId($sender_id) не соответствует заголовку source ($msg_source)", undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 6, ErrMsg => "Envelope SenderId doesn't correspond to message source", Type => $sig_type};
        }

        # Если в сообщении нет ни одной подписи
        if (scalar @$signatures < 1) {
            # Залогировать предупреждение
            $self->log('warning', 'check_signatures: No signatures found');
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, "Не найдено ни одной подписи", undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 6, ErrMsg => 'No signatures found', Type => $sig_type};
        }

        # Для каждой подписи нужно проверить, что такой сертификат есть в базе
        # Проверить все сертификаты, даже если есть ошибки - залогируем их и после этого вернём первую произошедшую ошибку
        my $err_result; # результат с ошибкой
        # Флаг наличия подписи контролёра
        my $controller_signature_exists = 0;
        # Перебрать список подписей
        for my $s (@$signatures) {
            # Получить из подписи фингерпринт и путь
            my $fingerprint = $s->{FingerPrint};
            my $sigpath = $s->{SignaturePath};
            # Если фингерпринт не найден или пустой
            if (!defined $fingerprint || $fingerprint eq '') {
                # Залогировать предупреждение
                $self->log('warning', 'check_signatures: Fingerprint not found for signature: ' . $sigpath);
                # Сохранить ошибку
                $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, 'Отпечаток подписи не найден: ' . $sigpath, undef, $sender_id, $receiver_id, $doc_type);
                # Если результат с ошибкой ещё не был задан, то задать его
                unless (defined $err_result) {
                    $err_result = {Result => 1, ErrCode => 6, ErrMsg => 'Bad signature: fingerprint not found', Type => $sig_type};
                }
                # Продолжить перебор
                next;
            }
            # Запросить сертификат из базы
            my $r = $self->get_certificate($sender_id, $fingerprint);
            # Если результат содержит ошибку
            if ($r->{Result} ne '0') {
                # Залогировать сервисную информацию
                $self->log('info', 'check_signatures: Cannot find certificate in database: ' . $sender_id . ', ' . $fingerprint);
                # Продолжить перебор
                next;
            }
            # Если у сертификата роль контролёра
            if ($r->{OperatorRole} == $CyberFT::OperatorRole::CONTROLLER) {
                # Установить флаг наличия подписи контролёра
                $controller_signature_exists = 1;
            }
            # Добавить в список проверенных подписей фингерпринт и отправителя
            push @$checked_signatures, {fingerprint => $fingerprint, signer => $sender_id};
        }
        # Если был задан результат с ошибкой
        if (defined $err_result) {
            # Вернуть результат с ошибкой
            return $err_result;
        }
        # Если не найдена подпись контролёра
        if ($controller_signature_exists == 0) {
            # Залогировать предупреждение
            $self->log('warning', 'check_signatures: Document has no controller signature');
            # Сохранить ошибку
            $self->save_error(ERR_SIGNATURE_CHECK, $doc_id, 'В документе отсутствует подпись контролера', undef, $sender_id, $receiver_id, $doc_type);
            # Вернуть результат с ошибкой
            return {
                Result            => 1,
                ErrCode           => 10,
                ErrMsg            => 'Controller signature is missing',
                CheckedSignatures => $checked_signatures,
            };
        }
    }
    # Вернуть результат с успехом
    return {Result => 0, ErrCode => 0, ErrMsg => "", Type => $sig_type, CheckedSignatures => $checked_signatures, Type => $sig_type};
}

# Метод получает сертификат участника из базы
sub get_certificate {
    my $self = shift;
    # Параметр ид участника
    my $member_id = shift;
    # Параметр фингерпринта
    my $fingerprint = shift;

    # Объединить код участника с фингерпринтом и получить «код ключа»
    my $key_code = $member_id . '-' . $fingerprint;
    # Сформировать параметры для запроса к базе
    my $params = {
        FromTerminal => undef,
        Terminal => $member_id,
        KeyCode => $key_code,
        CertCenter => 0,
    };

    # Сделать запрос к базе
    my $result = $self->{db}->get_member_cert_3($params);

    # Если результат содержит ошибку
    if ($result->{Result} ne '0') {
        my ($err_code, $err_msg);
        # Если значение результата равно 1
        if ($result->{Result} eq '1') {
            # Получить код и описание ошибки из результата
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        } else {
            # Залогировать нестандартную ошибку
            $self->log('error', "get_certificate: ($member_id, $fingerprint):".
                       "get_member_cert_3 error: " . $result->{ErrCode} . ': ' . $result->{ErrMsg});
            # Сохранить ошибку
            $self->save_error(ERR_DATABASE);
            # Задать код ошибки и сообщение об ошибке
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            # Установить флаг необходимости проверки базы данных
            $self->{db_check_needed} = 1;
        }
        # Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg};
    }
    # Получить сертификат из результата запроса
    my $cert = $result->{KeyBody};
    # Получить тип участника из результата запроса
    my $member_type = $result->{MemberType};
    # Вернуть результат с набором выходных параметров
    return {Result => 0, ErrCode => 0, ErrMsg => "", Certificate => $cert, MemberType => $member_type, OperatorRole => $result->{OperatorRole}};
}

# Метод присоединяет подписи к сообщению
sub link_message_signatures {
    my $self = shift;
    # Параметр объекта с параметрами
    my %p = @_;
    # Параметр конверта
    my $envelope = $p{envelope};
    # Параметр ид сообщения
    my $message_id = $p{message_id};
    # Параметр подписей
    my $signatures = $p{signatures};
    # Параметр отправителя
    my $sender_id = $envelope->{SenderId};
    # Параметр ид документа
    my $doc_id = $envelope->{DocId};
    # Перебрать все подписи
    for my $signature (@$signatures) {
        # Получить подписанта из подписи
        my $signer = $signature->{signer};
        # Получить фингерпринт из подписи
        my $fingerprint = $signature->{fingerprint};
        # Оформить массив параметров для запроса к базе
        my $params = {
            FromTerminal => undef,
            Message      => $message_id,
            Terminal     => $signer,
            KeyCode      => $signer . '-' . $fingerprint,
            IsError      => 0,
            ErrorInfo    => '',
            CertCenter   => 0,
        };

        # Сделать запрос к базе на добавление сертификата к сообщению
        my $result = $self->{db}->add_message_cert($params);

        # Если результат содержит ошибку
        if ($result->{Result} ne '0') {
            # Сохранить ошибку добавления сертификата
            $self->save_error(ERR_ADD_MESSAGE_CERT, $doc_id, $fingerprint, $result->{ErrMsg}, $sender_id, $envelope->{ReceiverId}, $envelope->{DocType});
            if ($result->{Result} eq '1') {
                # Уровень предупреждения: только логирование
                # Залогировать предупреждение
                $self->log('warning', "link_message_signatures: ($doc_id, $message_id, $signer, $fingerprint):".
                           " add_message_cert error: " . $result->{ErrCode} . ': ' . $result->{ErrMsg});
            } else {
                # Залогировать ошибку
                $self->log('error', "link_message_signatures: ($doc_id, $message_id, $signer, $fingerprint):".
                           " add_message_cert error: " . $result->{ErrCode} . ': ' . $result->{ErrMsg});
                # Сохранить ошибку
                $self->save_error(ERR_DATABASE);
                # Установить флаг необходимости проверки базы данных
                $self->{db_check_needed} = 1;
            }
        }
    }
}

# Метод проверяет наличие документа в базе
sub check_if_doc_exists_in_db {
    my $self = shift;
    # Параметр объекта с параметрами
    my %p = @_;
    # Параметр отправителя
    my $sender_id = $p{sender_id};
    # Параметр ид документа
    my $doc_id = $p{doc_id};
    # Запрос на поиск в базе документа с указанным отправителем и ид
    my ($exists) = $self->{db}->dbh->selectrow_array(
        q{
            select 1 from cyberft.w_messages
            where snd_full_swift_code = ? and sender_msg_code = ?
        },
        undef, $sender_id, $doc_id,
    );
    # Ошибка запроса
    if ($self->{db}->dbh->err()) {
        # Залогировать ошибку
        $self->log('error', "check_if_doc_exists_in_db: ($sender_id, $doc_id): db error: " . $self->{db}->dbh->errstr());
        # Сохранить ошибку
        $self->save_error(ERR_DATABASE);
        $self->{db_check_needed} = 1;
        # Вернуть неопределённый результат
        return undef;
    }
    # Вернуть результат
    return $exists ? 1 : 0;
}

# Метод сохраняет ошибку в базу данных
sub save_error {
    my $self = shift;
    # Параметр кода ошибки
    my $err_number = shift;
    # Дополнительные параметры ошибки
    my $param1 = shift // '';
    my $param2 = shift // '';
    my $param3 = shift // '';
    my $sender = shift;
    # Параметр получателя
    my $receiver = shift;
    # Параметр типа документа
    my $doc_type = shift;
    # Сохранение ошибки в базе данных
    my $res = $self->{db}->save_external_error({
        Error         => $err_number,
        Par1          => $param1,
        Par2          => $param2,
        Par3          => $param3,
        CftBic        => $sender,
        RecipientCode => $receiver,
        DocType       => $doc_type,
    });

    # Если возникла ошибка
    if ($res->{Result} ne '0') {
        # Залогировать предупреждение
        $self->log('warning', "save_error: ($err_number, $param1, $param2, $param3, $sender, $receiver, $doc_type):".
                   'save_external_error error: ' . $res->{ErrCode} . ': ' . $res->{ErrMsg});
    }
}

# Отладочный метод сохраняет временный файл
sub debug_save_tmp_doc {
    my $self = shift;
    # Параметры тела сообщения и файла сообщения
    my $msg_body = shift;
    my $msg_file = shift;

    # Если в конфиге не включена отладка, возврат
    if (!$self->{config}->{debug}) {
        return;
    }
    # Создать временный файл во временном каталоге из конфига
    my $tmp_file = temp_filename($self->{config}->{temp_dir}, 'debug');
    # Если определено тело сообщения
    if (defined $msg_body){
        eval {
            # Сохранить во временном файле тело сообщения
            write_file($tmp_file, \$msg_body);
        };
        # Если возникла ошибка
        if (my $err = $@) {
            # Залогировать ошибку
            $self->log('debug', "Error saving debug document: $err");
        } else {
            # Залогировать успех
            $self->log('debug', "Saved debug document to: $tmp_file");
        }
    } else {
        # Скопировать файл во временный файл
        my $ok = File::Copy::copy($msg_file, $tmp_file);
        # Если возникла ошибка копирования
        if (!$ok) {
            # Залогировать ошибку
            $self->log('debug', "Error copying debug document: $msg_file -> $tmp_file:  $!");
        } else {
            # Залогировать успех
            $self->log('debug', "Copied debug document to: $tmp_file");
        }
    }
}

# Метод загружает системный сертификат
sub load_system_certificate {
    my $self = shift;
	# Взять имя файла сертификата из настроек
    my $cert_file = $self->{config}->{sys_certificate_file};
	# Прочитать строку сертификата из файла
    read_file($cert_file, \my $cert_string);
	# Создать из строки объект X509
    my $x509 = Crypt::OpenSSL::X509->new_from_string($cert_string);
	# Получить поля Subject и Fingerprint
    my $subject = $x509->subject();
    my $fingerprint = uc($x509->fingerprint_sha1());
	# Убрать из фингерпринта двоеточия 
    $fingerprint =~ s/://g;
	# Назначить сертификат, subject и фингерпринт атрибутам класса
    $self->{sys_cert} = $cert_string;
    $self->{sys_cert_subject} = $subject;
    $self->{sys_cert_fingerprint} = $fingerprint;
}

# Метод загружает закрытый ключ системы
sub load_system_private_key {
    my $self = shift;
    # Параметры имени файла и пароля берутся из конфига
    my $priv_key_file = $self->{config}->{sys_private_key_file};
    my $priv_key_pass = $self->{config}->{sys_private_key_password};
    # Прочитать ключ из файла с указанными параметрами
    my $priv_key_string = $self->read_private_key_from_file($priv_key_file, $priv_key_pass);
    # Сохранить ключ в атрибуте класса
    $self->{sys_pkey} = $priv_key_string;
}

# Метод читает закрытый ключ из файла
sub read_private_key_from_file {
    my $self = shift;
    # Параметры имени файла и пароля
    my ($filename, $password) = @_;
    my $key_string;
    # Если не задан пароль
    if (!$password) {
        # Прочитать из файла в переменную key_string
        read_file($filename, \$key_string);
    } else {
        # Создать PEM-объект
        my $pem = Convert::PEM->new(
            Name => 'RSA PRIVATE KEY',
            ASN  => qq{
                RSAPrivateKey SEQUENCE {
                    version INTEGER,
                    n INTEGER,
                    e INTEGER,
                    d INTEGER,
                    p INTEGER,
                    q INTEGER,
                    dp INTEGER,
                    dq INTEGER,
                    iqmp INTEGER
                }
            }
        );
        # Прочитать ключ в объект из файла с использованием пароля
        my $pkey = $pem->read(Filename => $filename, Password => $password);
        # Поместить в key_string PEM-объект, преобразованный в строку
        $key_string = $pem->encode(Content => $pkey);
    }
    # Вернуть строку с ключом
    return $key_string;
}

# После возникновения необработанной ошибки во время обработки фрэйма, нужно вызвать recover.
# Метод разрывает и заново устанавливает соединение с брокером.
# Также проверяется соединение с базой. Если его нет, то оно восстанавливается.
sub recover {
    my $self = shift;
    # Если создан объект брокера
    if (defined $self->{broker}) {
        # Закрыть соединение с брокером
        $self->{broker}->disconnect();
        # Открыть соединение с брокером
        $self->connect_broker();
    }
    # Если отсутствует пинг к базе данных или она не определена, открыть базу данных
    unless (defined($self->{db}) && $self->{db}->ping()) {
        # Залогировать ошибку
        $self->log('error', 'Database connection lost');
        $self->connect_database();
    }
}

# Метод закрывает все соединения
sub cleanup {
    my $self = shift;
    # Если создан объект брокера
    if (defined $self->{broker}) {
        # Закрыть соединение с брокером
        $self->{broker}->disconnect();
    }
    # Закрыть базу данных, если определена
    if (defined $self->{db}) {
        $self->{db}->disconnect();
    }
}

# Метод логирует сообщение
sub log {
    my $self = shift;
    # Параметр приоритета
    my $priority = shift;
    # Параметр сообщения
    my $msg = shift;
    # Если определён префикс лога, добавить к сообщению
    if (defined $self->{log_prefix}) {
        $msg = $self->{log_prefix}.$msg;
    }
    # Вызвать функцию логирования с параметрами
    $self->{config}->{log_func}->($priority, $msg);
}

1;