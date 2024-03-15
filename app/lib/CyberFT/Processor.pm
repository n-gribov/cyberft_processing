package CyberFT::Processor;

use strict;
use utf8;
use Data::Dumper;
use Data::UUID ();
use Encode;
use Convert::PEM ();
use Digest::MD5 ();
use MIME::Base64 ();
use Encode ();
use Time::HiRes ();
use Crypt::OpenSSL::X509 ();
use File::Copy ();
use Time::Local ();
use Date::Calc ();
use File::Path ();
use MIME::Lite ();
use POSIX qw(strftime);
use Text::Iconv;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );

use CyberFT::Broker;
use CyberFT::Database;
use CyberFT::Envelope;
use CyberFT::Errors;
use CyberFT::OperatorRole;

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

# Инициализация.
# Обязательные параметры:
#     broker_host, broker_port, broker_username, broker_password, db_data_source, db_username, db_password,
#     sys_id, sys_certificate_file, sys_private_key_file, sys_private_key_password, log_func.
# Здесь параметр log_func - функция логирования. В нее будут передаваться два параметра:
#     уровень ("info", "warning", "error", "debug") и сообщение для записи в лог.
sub init {
    my $self = shift;
	# Получить список входных параметров
    my %params = @_;
	# Записать параметры в конфиг
    $self->{config} = \%params;

    # Параметры, которые должны присутствовать:
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
        bicdir_dir
        sys_email
    );
	# Перебрать список обязательных параметров
    for my $p (@required_params) {
		# Если в конфиге нет такого параметра
        unless ($self->{config}->{$p}) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Required parameter not found: '$p'"};
        }
    }
	# Перебрать параметры с именами папок
    for my $dir_param ('temp_dir', 'broker_spool_dir', 'bicdir_dir') {
		# Если не существует папки
        unless (-d $self->{config}->{$dir_param}) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Bad directory parameter: $dir_param"};
        }
    }
	# Залогировать сервисное сообщение
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

    # Подключимся к брокеру сообщений
    my $r = $self->connect_broker();
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Initialization failed: Mesasge broker error: ' . $r->{ErrMsg});
		# Вернуть результат
        return $r;
    }

    # Получим системный ключ и сертификат для подписи ответных сообщений
	# Залогировать сервисное сообщение
    $self->log('info', 'Reading signing keys');
    eval {
		# Загрузить закрытый ключ системы
        $self->load_system_private_key();
		# Загрузить сертификат системы
        $self->load_system_certificate();
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Залогировать ошибку
        $self->log('error', 'Initialization failed: System certificate / private key loading error: ' . $err);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'System certificate / private key loading error: ' . $err};
    }
	# Залогировать сервисное сообщение
    $self->log('info', 'Initialization is complete');
	# Вернуть успешный результат
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
			# Вернуть успешный результат
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
	# Интервал
    my $interval = 1 * 60;
	# Если неизвестно время последней проверки или оно устарело
    if (!defined($self->{db_last_checked}) || time() - $self->{db_last_checked} > $interval) {
		# Устновить флаг необходимости проверки
        $self->{db_check_needed} = 1;
    }
	# Если установлен фоаг необхощдимости проверки
    if ($self->{db_check_needed}) {
		# Если нет соединения с базой или она не пингуется
        unless (defined($self->{db}) && $self->{db}->ping()) {
			# Залогировать ошибку
            $self->log('error', 'Database connection lost');
			# Открыть соединение с базой данных
            $self->connect_database();
        }
		# Очистить фоаг необходимости проверки
        $self->{db_check_needed} = 0;
		# Установить время последней проверки
        $self->{db_last_checked} = time();
    }
}

# Метод открывает соединение с брокером сообщений
sub connect_broker {
    my $self = shift;
	# Залогировать сервисное сообщение
    $self->log(
        'info',
        'Connecting to the message broker: ' . $self->{config}->{broker_host} . ':' . $self->{config}->{broker_port}
    );
	# Обновить время бездействия брокера
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

	# Залогировать сервисное сообщение
    $self->log('info', 'Subscribing to the queue: ' . $self->{config}->{sys_id});
	# Подписаться на свою очередь, указанную в конфиге
    my $broker_sub_res = $self->{broker}->subscribe($self->{config}->{sys_id});
	# Если возникла ошибка
    if ($broker_sub_res->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Message broker subscribe error: ' . $broker_sub_res->{ErrMsg});
		# Сохранить ошибку брокера
        $self->save_broker_conn_error();
		# Вернуть результат
        return $broker_sub_res;
    }
	# Вернуть успешный результат
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
		# Очистить флаг необходимости повторного соединения с брокером
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

# Метод реализаует главный цикл обработки сообщений
sub process_loop {
    my $self = shift;
    my $done = shift; # ссылка на переменную-флаг для остановки цикла.
	# Пока цикл не остановлен
    while (!$$done) {
        eval {
			# Вызвать обработчик
            my $r = $self->process_step(1);
			# Если результат содержит ошибку
            if ($r->{Result} ne '0') {
				# Залогировать предупреждение
                $self->log('warning', 'process_loop: process_step error: ' . $r->{ErrMsg});
            }
			# Очистить префикс логирования
            $self->{log_prefix} = undef;
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Залогировать ошибку
            $self->log('error', "process_loop: process_step died: $err");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_PROCESSING);
			# Очистить префикс логирования
            $self->{log_prefix} = undef;
			# Восстановить соединения
            $self->recover;
			# Пауза
            sleep(3);
        }
    }
}

# Метод получает и обрабатывет один фрейм от брокера
sub process_step {
	# Получить входные параметры
    my $self = shift;
    my $timeout = shift;
	# Очистить префикс логирования
    $self->{log_prefix} = undef;

    # Проверить / восстановить соединения с базой и брокером при необходимости
    $self->check_database_connection();
    $self->check_broker_connection();

    # Получить следующее сообщение
    my $r = $self->{broker}->recv_frame($timeout);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Broker recv_frame error: ' . $r->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_BROKER_RECV);
		# Установить флаг необходимости повторного соединения с брокером
        $self->{broker_reconnect_needed} = 1;
		# Вернуть результат
        return $r;
    }
	# Получить фрейм из результата
    my $frame = $r->{Frame};
	# Если фрейм не получен
    unless (defined $frame) {
		# Вернуть успешный результат о том, что не получен фрейм
        return {Result => 0, ErrCode => 0, ErrMsg => 'No frame received'};
    }
	# Если фрейм не содержит MESSAGE
    if ($frame->command ne 'MESSAGE') {
		# Залогировать ошибку
        $self->log('error', 'Skipping frame, not a MESSAGE: ' . $r->{Frame}->command);
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_BROKER_RECV);
		# Установить флаг необходимости повторного соединения с брокером
        $self->{broker_reconnect_needed} = 1;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Skipped (bad frame type)'};
    }

    # Обновить таймер простоя брокера без новых сообщений
    $self->{broker_idle_timer} = time();

    # Получить информационные заголовки из брокера
    # Они позволят ответить ошибкой, если произошла проблема получения, парсинга или валидации документа
    my $info_sender_id = $frame->headers->{sender_id};
    my $info_doc_id = $frame->headers->{doc_id};
    my $info_doc_type = $frame->headers->{doc_type};
    my $info_receiver_id = $self->{db}->get_receiver_code($info_doc_id, $info_sender_id);
	# Установить префикс логирования
    $self->{log_prefix} = "[$info_sender_id-$info_doc_id] ";
	# Получить текущее время
    my $timestamp = timestamp_hires();
	# Залогировать сервисное сообщение с параметрами фрейма
    $self->log('info', "In: Timestamp=$timestamp; Frame headers: " . remove_crlf(dumper($frame->headers)));

    # Определить, от кого сообщение попало в очередь - должен быть наш id
    my $msg_source = $frame->headers->{source};
    my $msg_source_ip = $frame->headers->{'source-ip'};
	# Если сообщение не от нас
    if ($msg_source ne $self->{config}->{sys_id}) {
		# Залогировать предупреждение
        $self->log('warning', "Bad source (source=$msg_source, source-ip=$msg_source_ip) - ignoring");
		# Послать ACK
        $self->{broker}->send_ack($frame);
		# Вернуть результат с ошибкой
        return { Result => 1, ErrCode => 10, ErrMsg => "Bad source ($msg_source)" };
    }

    my ($msg_body, $msg_file, $msg_len);
    # Тело сообщения лежит или в отдельном файле директории spool брокера,
	# или находится в теле фрeйма stomp
	# Это можно определить по заголовку "file_id".
    my $file_id = $frame->headers->{file_id};
	# Если ид файла задан и не пустой
    if (defined $file_id && $file_id =~ /\S+/) {
		# Получить папку хранилища брокера из конфига
        my $broker_spool_dir = $self->{config}->{broker_spool_dir};
		# Удалить последний "/"
        $broker_spool_dir =~ s|\/$||;
		# Составить имя входного файла
        my $input_file = $broker_spool_dir . '/' . $msg_source . '-' . $file_id . '.blob';
		# Залогировать сервисное сообщение
        $self->log('info', "Input file: $input_file");
		# Если не существует входной файл
        unless (-f $input_file) {
			# Залогировать предупреждение
            $self->log('warning', "Input file does not exist: ($input_file)");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_INPUT_FILE_NOT_FOUND, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
			# Отправить ответ на ошибочный документ
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_INPUT_FILE_NOT_FOUND, CyberFT::Errors::desc(ERR_INPUT_FILE_NOT_FOUND),
            );
			# Послать ACK
            $self->{broker}->send_ack($frame);
			# Вернуть результат с ошибкой
            return { Result => 1, ErrCode => 10, ErrMsg => 'Input file does not exist' };
        }

        # Проверить, не превышен ли максимальный размер XML-конверта
        $msg_len = -s $input_file;
		# Если размер больше максимального
        if ($msg_len > $self->{config}->{envelope_max_size}) {
			# Залогировать предупреждение
            $self->log('warning', "Maximum envelope size exceeded: $msg_len");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_MAX_ENVELOPE_SIZE, $info_doc_id, $msg_len, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
			# Отправить ответ на ошибочный документ
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_MAX_ENVELOPE_SIZE, CyberFT::Errors::desc(ERR_MAX_ENVELOPE_SIZE),
            );
			# Послать ACK
            $self->{broker}->send_ack($frame);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => 'Maximum envelope size exceeded'};
        }

        # Если документ слишком большой, обработать его с использованием временного файла
        if ($msg_len > $MAX_IN_MEMORY_DOC_SIZE) {
			# Получить имя временного файла
            $msg_file = temp_filename($self->{config}->{temp_dir}, 'processor');
			# Залогировать сервисное сообщение
            $self->log('info', "Moving document to: $msg_file");
			# Если не удалось переместить входной файл во временный
            unless (File::Copy::move($input_file, $msg_file)) {
				# Залогировать ошибку
                $self->log('error', "Input file move error: ($input_file, $msg_file): $!");
				# Сохранить ошибку в базе данных
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
				# Отправить ответ на ошибочный документ
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
				# Послать ACK
                $self->{broker}->send_ack($frame);
				# Вернуть результат с ошибкой
                return {Result => 1, ErrCode => 10, ErrMsg => 'Input file move error'};
            }
        } else {
            eval {
				# Прочитать тело сообщения из входящего файла
                read_file($input_file, \$msg_body);
				# Удалить входящий файл
                unlink($input_file);
            };
			# Если возникла ошибка
            if (my $err = $@) {
				# Залогировать ошибку
                $self->log('error', "Input file read error: $err");
				# Сохранить ошибку в базе данных
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
				# Отправить ответ на ошибочный документ
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
				# Послать ACK
                $self->{broker}->send_ack($frame);
				# Вернуть результат с ошибкой
                return { Result => 1, ErrCode => 10, ErrMsg => 'Input file read error' };
            }
        }
    } else {
        # Проверить, не превышен ли максимальный размер XML-конверта.
        $msg_len = length($frame->body);
		# Если длина сообщения больше заданной в конфиге
        if ($msg_len > $self->{config}->{envelope_max_size}) {
			# Залогировать предупреждение
            $self->log('warning', "Maximum envelope size exceeded: $msg_len");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_MAX_ENVELOPE_SIZE, $info_doc_id, $msg_len, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
			# Отправить ответ на ошибочный документ
            $self->reply_doc_error(
                $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                ERR_MAX_ENVELOPE_SIZE, CyberFT::Errors::desc(ERR_MAX_ENVELOPE_SIZE),
            );
			# Послать ACK
            $self->{broker}->send_ack($frame);
			# Вернуть результат с ошибкой
            return { Result => 1, ErrCode => 10, ErrMsg => 'Maximum envelope size exceeded' };
        }

        # Если документ слишком большой, обработать его с использованием временного файла
        if ($msg_len > $MAX_IN_MEMORY_DOC_SIZE) {
			# Получить имя временного файла
            $msg_file = temp_filename($self->{config}->{temp_dir}, 'processor');
			# Залогировать сервисное сообщение
            $self->log('info', "Saving document to: $msg_file");
			# Записать тело фрейма во временный файл
            eval {
                write_file($msg_file, \$frame->body);
            };
			# Если возникла ошибка
            if (my $err = $@) {
				# Залогировать ошибку
                $self->log('error', "Input file write error: $msg_file: $err");
				# Сохранить ошибку в базе данных
                $self->save_error(ERR_FILE_ACCESS, $info_doc_id, undef, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
				# Отправить ответ на ошибочный документ
                $self->reply_doc_error(
                    $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
                    ERR_FILE_ACCESS, CyberFT::Errors::desc(ERR_FILE_ACCESS),
                );
				# Послать ACK
                $self->{broker}->send_ack($frame);
				# Вернуть результат с ошибкой
                return { Result => 1, ErrCode => 10, ErrMsg => 'Input file read error' };
            }
        } else {
			# Получить тело сообщения из фрейма
            $msg_body = $frame->body;
        }
    }
	# Определить, находится ли сообщение в памяти
    my $inmemory = (defined $msg_body) ? 1 : 0;
	# Залогировать сервисное сообщение
    $self->log('info', "Document size: $msg_len; In-memory processing: $inmemory");

    # Обработать сообщение с параметрами
    $self->process_message(
        msg_body         => $msg_body,
        msg_file         => $msg_file,
        msg_len          => $msg_len,
        msg_source       => $msg_source,
        msg_source_ip    => $msg_source_ip,
        info_sender_id   => $info_sender_id,
        info_doc_id      => $info_doc_id,
        info_doc_type    => $info_doc_type,
        info_receiver_id => $info_receiver_id,
    );

    # Удалить временный файл, если он существует
    if (defined $msg_file && -f $msg_file) {
        unlink($msg_file);
    }

    # Переход к следующему сообщению
	# Послать ACK
    my $r = $self->{broker}->send_ack($frame);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Broker send_ack error: ' . $r->{ErrMsg});
		# Установить флаг необходимости повторного соединения с брокером
        $self->{broker_reconnect_needed} = 1;
		# Вернуть результат
        return $r;
    }
	# Вернуть успешный результат
    return { Result => 0, ErrCode => 0, ErrMsg => 'OK' };
}

# Метод обрабатывет отдельное сообщение (xml-конверт)
sub process_message {
	# Получить входные параметры
    my ($self, %opts) = @_;
	# Получить поля сообщения
    my $msg_body         = $opts{msg_body};
    my $msg_file         = $opts{msg_file};
    my $msg_len          = $opts{msg_len};
    my $msg_source       = $opts{msg_source};
    my $msg_source_ip    = $opts{msg_source_ip};
    my $info_sender_id   = $opts{info_sender_id};
    my $info_doc_id      = $opts{info_doc_id};
    my $info_doc_type    = $opts{info_doc_type};
    my $info_receiver_id = $opts{info_receiver_id},

	# Получить длину сообщения из длины файла
    # my $msg_len = -s $msg_file;

    # Распарсить сообщение
    my $r = CyberFT::Envelope::parse(xml_string => $msg_body, xml_file => $msg_file);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', "Envelope parse error ($info_doc_id): " . $r->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_ENVELOPE_PARSE, $info_doc_id, $r->{ErrMsg}, undef, $info_sender_id, $info_receiver_id, $info_doc_type);
		# Отправить ответ на ошибочный документ
        $self->reply_doc_error(
            $msg_source, $info_sender_id, $info_doc_id, $info_doc_type,
            ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE),
        );
        return;
    }
	# Получить конверт из результата
    my $envelope = $r->{Envelope};
	# Получить поля сообщения из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
	# Залогировать сервисное сообщение
    $self->log('info', 'Parsed envelope: ' . remove_crlf(dumper($envelope)));
	# Установить префикс логирования
    $self->{log_prefix} = "[$sender_id-$doc_id] ";

    # Изменить статус документа
    $self->change_status($envelope, 15); # Доставлен следующему узлу.

    # Проверить подписи
    if ($self->skip_signature_validation($doc_type)) {
		# Залогировать сервисное сообщение
        $self->log('info', 'Signature validation is skipped');
    } else {
		# Проверить подписи в конверте
        my $r = $self->check_signatures($envelope, $msg_source, $msg_body, $msg_file);
		# Если результат успешен
        if ($r->{Result} eq '0') {
			# Получить список подписей из результата
            my $signatures = $r->{CheckedSignatures};
			# Получить список фингерпинтов из списка подписей
            my $fps_str = join(',', map {$_->{fingerprint}} @$signatures);
			# Залогировать сервисное сообщение
            $self->log('info', "Checked signatures: Certificate fingerprints: $fps_str");
        } else {
			# Залогировать предупреждение
            $self->log('warning', 'Signature check error: ' . $r->{ErrMsg});
			# Изменить статус документа
            $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
			# Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', ERR_SIGNATURE_CHECK, CyberFT::Errors::desc(ERR_SIGNATURE_CHECK));
			# Вернуться
            return;
        }
    }

    # Запустить различные виды обработки в зависимости от типа документа
    if ($doc_type eq 'BICDirRequest') {
		# Обработать запрос на обновление справочника
        $self->process_bicdir_request($msg_body, $msg_file, $envelope);
    }
    elsif ($doc_type eq 'BICDir') {
		# Обработать обновление справочник
        $self->process_bicdir($msg_body, $msg_file, $envelope);
    }
    elsif ($doc_type eq 'CFTStatusReport') {
		# Обработать статус-репорт
        $self->process_status_report($msg_body, $msg_file, $envelope);
    }
    else {
		# Обработать неизвестный тип
        $self->process_unknown($msg_body, $msg_file, $envelope);
    }
}

# Метод определяет возможность пропуска проверки продписи
sub skip_signature_validation {
	# Получить входные параметры
    my ($self, $doc_type) = @_;
	# Не требуется проверка, если документ типа CFTStatusReport
    return $doc_type eq 'CFTStatusReport';
}

# Метод обрабатывает запрос обновления справочника участников
sub process_bicdir_request {
	# Получить входные параметры
    my ($self, $msg_body, $msg_file, $envelope) = @_;
	# Получить поля сообщения из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
	# Сегодняшняя и вчерашняя даты
    my @today = Date::Calc::Today;
    my @yesterday = Date::Calc::Add_Delta_YMD(@today, 0, 0, -1);
	# Если конверт содержит запрос на полное обновление
    if (defined $envelope->{BICDirReq_Full_ContentFormat}) {
		# Формат обновления
        my $format = $envelope->{BICDirReq_Full_ContentFormat};
		# Дата последнего обновления
        my $last_update_date = $envelope->{BICDirReq_Full_LastUpdateDate};
		# Флаг пропуска, если не было изменений
        my $skip_if_unchanged = $envelope->{BICDirReq_Full_SkipIfUnchanged};

        # Нужно отправить последнее обновление. Если еще нет сегодняшнего, то отправим вчерашнее
        my @date;
        my $filename;
		# Получить имя сегодняшнего файла
        my $today_filename = $self->get_bicdir_filename('all', sprintf('%04d-%02d-%02d', @today));
		# Получить имя вчерашнего файла
        my $yesterday_filename = $self->get_bicdir_filename('all', sprintf('%04d-%02d-%02d', @yesterday));
		# Если существует сегодняшний файл
        if (-f $today_filename) {
			# Дату установить на сегодня
            @date = @today;
			# Имя файла установить на сегодняшнее
            $filename = $today_filename;
        }
		# Иначе если сушествует вчерашний файл
        elsif (-f $yesterday_filename) {
			# Дату установить на вчера
            @date = @yesterday;
			# Имя файла установить на вчерашнее
            $filename = $yesterday_filename;
        }
        else {
			# Залогировать ошибку
            $self->log('error', "Full BICDir update file not found: ($today_filename, $yesterday_filename)");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_BICDIR_FILE_MISSING, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Изменить статус документа
            $self->change_status($envelope, 17); # Доставлен получателю
			# Послать статус-репорт
            $self->send_status_report($envelope, 'ACDC', ERR_BICDIR_FILE_MISSING, CyberFT::Errors::desc(ERR_BICDIR_FILE_MISSING));
            return;
        }
		# Залогировать сервисное сообщение
        $self->log('info', 'BICDir request full: ' . sprintf('%04d-%02d-%02d', @date));

        # В полном обновлении только один архив
        my @archives = ($filename);

        # Собрать и отправить ответный документ
        my $err = $self->send_bicdir_update_envelope($envelope, 'all', \@archives);
		# Если возникла ошибка
        if ($err) {
			# Изменить статус документа
            $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
			# Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', $err, CyberFT::Errors::desc($err));
            return;
        }
    } elsif (defined $envelope->{BICDirReq_Incr_ContentFormat}) {
        # Это запрос инкрементальных обновлений
		# Формат обновления
        my $format = $envelope->{BICDirReq_Incr_ContentFormat};
		# Начальная дата
        my $start_date = $envelope->{BICDirReq_Incr_StartDate};
		# Конечная дата
        my $end_date = $envelope->{BICDirReq_Incr_EndDate};

        # Провалидировать даты
        my $val = $self->validate_bicdir_increment_dates($start_date, $end_date);
		# Если возникла ошибка
        if ($val->{err}) {
			# Залогировать предупреждение
            $self->log('warning', "Bad datetimes for increment BICDir: ($start_date, $end_date): " . $val->{err});
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_ENVELOPE_PARSE, $doc_id, 'BICDirectoryUpdate dates validation failed', undef, $sender_id, $receiver_id, $doc_type);
			# Изменить статус документа
            $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
			# Послать статус-репорт
            $self->send_status_report($envelope, 'RJCT', ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE));
            return;
        }
		# Установить начальную и конечную дату
        my @start_date = @{$val->{start_date}};
        my @end_date = @{$val->{end_date}};
		# Залогировать сервисное сообщение
        $self->log('info', 'BICDir request increment: ' . sprintf('%04d-%02d-%02d', @start_date) . ' - ' . sprintf('%04d-%02d-%02d', @end_date));
        # Возможно, конечная дата не указана в архиве, а начальная дата вчерашняя, но архив за вчера еще не сформирован
        if (Date::Calc::Date_to_Days(@start_date) > Date::Calc::Date_to_Days(@end_date)) {
			# Залогировать предупреждение
            $self->log('warning', 'No BICDir archives found for requested dates');
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_BICDIR_FILE_MISSING, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Изменить статус документа
            $self->change_status($envelope, 17); # Доставлен получателю
			# Послать статус-репорт
            $self->send_status_report($envelope, 'ACDC', ERR_BICDIR_FILE_MISSING, CyberFT::Errors::desc(ERR_BICDIR_FILE_MISSING));
            return;
        }

        # Cоставить список архивов, которые нужно отправить.
        my @archives;
        my @date = @start_date;
		# Перебрать даты от начальной до конечной
        while (Date::Calc::Date_to_Days(@date) <= Date::Calc::Date_to_Days(@end_date)) {
			# Добавить в список архивов имя файла обновления
            push @archives, $self->get_bicdir_filename('increment', sprintf('%04d-%02d-%02d', @date));
			# Перейти к следующей дате
            @date = Date::Calc::Add_Delta_YMD(@date, 0, 0, 1);
        }

        # Собрать и отправить ответный документ
        my $err = $self->send_bicdir_update_envelope($envelope, 'increment', \@archives);
		# Если возникла ошибка
        if ($err) {
			# Если отсутствует файл обновления
            if ($err == ERR_BICDIR_FILE_MISSING) {
				# Изменить статус документа
                $self->change_status($envelope, 17); # Доставлен получателю
				# Послать статус-репорт
                $self->send_status_report($envelope, 'ACDC', ERR_BICDIR_FILE_MISSING, CyberFT::Errors::desc(ERR_BICDIR_FILE_MISSING));
            } else {
				# Изменить статус документа
                $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
				# Послать статус-репорт
                $self->send_status_report($envelope, 'RJCT', $err, CyberFT::Errors::desc($err));
            }
            return;
        }
    } else {
        # Какой-то неправильный запрос
		# Залогировать предупреждение
        $self->log('warning', 'Unknown BICDir request type');
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_BICDIR_UNKNOWN_TYPE, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_BICDIR_UNKNOWN_TYPE, CyberFT::Errors::desc(ERR_BICDIR_UNKNOWN_TYPE));
        return;
    }
	# Изменить статус документа
    $self->change_status($envelope, 17); # Доставлен получателю
	# Послать статус-репорт
    $self->send_status_report($envelope, 'ACDC', 0, '');
}

# Метод валидирует даты в запросе инкрементальных обновлений
sub validate_bicdir_increment_dates {
	# Получить входные параметры
    my ($self, $start_date, $end_date) = @_;
	# Сегодняшняя дата
    my @today = Date::Calc::Today;
	# Вчерашняя дата
    my @yesterday = Date::Calc::Add_Delta_YMD(@today, 0, 0, -1);
	# Позавчерашняя дата
    my @day_before_yesterday = Date::Calc::Add_Delta_YMD(@yesterday, 0, 0, -1);
	# Дата последнего инкрементального обновления
    my @last_increment_date = @yesterday;
	# Если не существует вчерашний файл
    unless (-f $self->get_bicdir_filename('increment', sprintf('%04d-%02d-%02d', @yesterday))) {
		# Установить дату последнего инкрементального обновления на позавчерашнюю
        @last_increment_date = @day_before_yesterday;
    }

    my @start_date;
	# Если параметр начальной даты в правильном формате
    if ($start_date =~ /^(\d\d\d\d)-(\d\d)-(\d\d)/) {
		# Присвоить начальную дату из трёх частей Y, m, d
        @start_date = ($1, $2, $3);
    }
    else {
		# Вернуть ошибку
        return { err => 'Bad StartDate format' };
    }
	# Если начальная дата не валидна
    unless (Date::Calc::check_date(@start_date)) {
		# Вернуть ошибку
        return { err => 'StartDate check failed' };
    }
	# Если начальная дата позже чем вчерашняя
    if (Date::Calc::Date_to_Days(@start_date) > Date::Calc::Date_to_Days(@yesterday)) {
		# Вернуть ошибку
        return { err => 'Bad StartDate value' };
    }

    my @end_date;
	# Если не задана конечная дата
    if (!defined $end_date || $end_date eq '') {
		# Установить конечную дату на дату последнего инкрементального обновления
        @end_date = @last_increment_date;
    }
	# Если параметр конечной даты в правильном формате
	elsif ($end_date =~ /^(\d\d\d\d)-(\d\d)-(\d\d)/) {
		# Присвоить конечную дату из трёх частей Y, m, d
        @end_date = ($1, $2, $3);
		# Если конечная дата не валидна
        unless (Date::Calc::check_date(@end_date)) {
			# Вернуть ошибку
            return { err => 'EndDate check failed' };
        }
		# Если конечная дата позже чем вчерашняя
        if (Date::Calc::Date_to_Days(@end_date) > Date::Calc::Date_to_Days(@yesterday)) {
			# Вернуть ошибку
            return { err => 'Bad EndDate value' };
        }
		# Если начальная дата позже чем конечная
        if (Date::Calc::Date_to_Days(@start_date) > Date::Calc::Date_to_Days(@end_date)) {
			# Вернуть ошибку
            return { err => 'StartDate cannot be greater than EndDate' };
        }
    } else {
		# Вернуть ошибку
        return { err => 'Bad EndDate format' };
    }
	# Вернуть проверенные даты
    return { err => undef, start_date => \@start_date, end_date => \@end_date };
}

# Метод формирует путь к файлу обновления участников
sub get_bicdir_filename {
	# Получить входные параметры
    my ($self, $type, $date) = @_;
	# Получить папку обновлений из конфига
    my $dir = $self->{config}->{bicdir_dir};
	# Убрать последний "/"
    $dir =~ s|/$||;
	# Изменить формат даты
    $date =~ s/(\d\d\d\d)-(\d\d)-(\d\d)/$1$2$3/;
	# Если тип обновления инкрементальный
    if ($type eq 'increment') {
		# Вернуть путь для инкрементального обновления
        return $dir . '/' . 'BICDir_Increment_' . $date . '.zip';
    } else {
		# Вернуть путь для полного обновления
        return $dir . '/' . 'BICDir_All_' . $date . '.zip';
    }
}

# Метод формирует и отправляет конверт с обновлениями справочника участников
sub send_bicdir_update_envelope {
	# Получить входные параметры
    my ($self, $envelope, $type, $archives) = @_;
	# Получить поля сообщения из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_date = $envelope->{DocDate};
    my $sender_id = $envelope->{SenderId};
	
    my $tz;
	# Установить таймзону
    if (strftime('%z', localtime) =~ /^([+-]\d\d)(\d\d)$/) {
        $tz = $1 . ':' . $2;
    } else {
        $tz = '+00:00';
    }

    # Сформировать ответный документ BICDir
    my $body = '';
    $body .= q{<BICDirectoryUpdate xmlns="http://cyberft.ru/xsd/cftsys.02" xmlns:data="http://cyberft.ru/xsd/cftdata.02">};
    $body .= q{<data:RefDoc>};
    $body .= q{<data:RefDocId>} . $doc_id . q{</data:RefDocId>};
    $body .= q{<data:RefDocDate>} . $doc_date . q{</data:RefDocDate>};
    $body .= q{<data:RefSenderId>} . $sender_id . q{</data:RefSenderId>};
    $body .= q{</data:RefDoc>};
	# Перебрать список архивов
    for my $arch (@$archives) {
		# Получить файл обновления
        my ($bicdir, $err) = $self->get_bicdir($arch);
		# Если возникла ошибка
        if ($err) {
			# Залогировать предупреждение
            $self->log('warning', "Failed to get bicdir ($arch): $err");
			# Сохранить ошибку в базе данных
            $self->save_error(ERR_BICDIR_FILE_MISSING, $doc_id, undef, undef, $sender_id, $envelope->{ReceiverId}, $envelope->{DocType});
			# Вернуть ошибку
            return ERR_BICDIR_FILE_MISSING;
        }
		# Если тип обновления инкрементальный
        if ($type eq 'increment') {
			# Добавить в тело сообщения инкрементальный блок
            $body .= q{<IncrementLoad>};
            $body .= q{<Header>};
            $body .= q{<StartDate>} . $bicdir->{file_date} . 'T00:00:00' . $tz . q{</StartDate>};
            $body .= q{<EndDate>} . $bicdir->{file_date} . 'T23:59:59' . $tz . q{</EndDate>};
            $body .= q{<ReqCount>} . $bicdir->{num_records} . q{</ReqCount>};
            $body .= q{</Header>};
            $body .= q{<Content format="BICDirCSV/} . $bicdir->{version} . q{">};
            $body .= q{<data:RawData mimeType="application/zip" encoding="base64" charSet="}. $bicdir->{encoding} . q{" filename="} . $bicdir->{file_name} . q{">};
            $body .= $bicdir->{data_base64};
            $body .= q{</data:RawData>};
            $body .= q{</Content>};
            $body .= q{</IncrementLoad>};
        } else {
			# Добавить в тело сообщения полный блок
            $body .= q{<FullLoad>};
            $body .= q{<Header>};
            $body .= q{<LastUpdateDate>} . $bicdir->{created_at} . $tz . q{</LastUpdateDate>};
            $body .= q{<ReqCount>} . $bicdir->{num_records} . q{</ReqCount>};
            $body .= q{</Header>};
            $body .= q{<Content format="BICDirCSV/} . $bicdir->{version} . q{">};
            $body .= q{<data:RawData mimeType="application/zip" encoding="base64" charSet="}. $bicdir->{encoding} . q{" filename="} . $bicdir->{file_name} . q{">};
            $body .= $bicdir->{data_base64};
            $body .= q{</data:RawData>};
            $body .= q{</Content>};
            $body .= q{</FullLoad>};
        }
    };

    $body .= q{</BICDirectoryUpdate>};

	# Сгенерировать таймстампы
    my ($xml_date, $db_date) = gen_timestamps();

    # Поместить BICDir в конверт CyberFT
    my $r = CyberFT::Envelope::create_signed(
        doc_type         => 'BICDir',
        doc_date         => $xml_date,
        sender_id        => $self->{config}->{sys_id},
        receiver_id      => $sender_id,
        body_mime        => 'application/xml',
        body             => $body,
        cert_subject     => $self->{sys_cert_subject},
        cert_fingerprint => $self->{sys_cert_fingerprint},
        cert_file        => $self->{config}->{sys_certificate_file},
        pkey_file        => $self->{config}->{sys_private_key_file},
        pkey_pwd         => $self->{config}->{sys_private_key_password},
    );
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Failed to create signed bicdir envelope: '  . $r->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_PROCESSING, $doc_id, $r->{ErrMsg}, undef, $sender_id, $envelope->{ReceiverId}, $envelope->{DocType});
		# Вернуть ощибку
        return ERR_PROCESSING;
    }
	# Контент ответа
    my $rep_content = $r->{Content};
	# ид ответа
    my $rep_id = $r->{DocId};

    # Добавить ответ в базу
    my $r = $self->save_message_to_db(
        doc_id      => $rep_id,
        doc_type    => 'BICDir',
        doc_time    => $db_date,
        sender_id   => $self->{config}->{sys_id},
        receiver_id => $sender_id,
        msg         => $rep_content,
        msg_len     => length($rep_content),
    );
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to save reply bicdir to DB: ' . $r->{ErrCode} . ': ' . $r->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_SAVE_REPLY_BICDIR, $doc_id, $r->{ErrMsgDB}, undef, $sender_id, $envelope->{ReceiverId}, $envelope->{DocType});
		# Вернуть ошибку
        return ERR_PROCESSING;
    }
	# Залогировать сервисное сообщение
    $self->log('info', "Successfully sent BICDir envelope (type=$type) to $sender_id. DocId=$rep_id");
    return undef;
}

# Метод получает файл обновления из файловой системы и различные его параметры
sub get_bicdir {
	# Получить входные параметры
    my ($self, $zip_filename) = @_;

    my $bicdir = {};
    my $info_filename = $zip_filename . '.info';
	# Если имя файла в правильном формате
    if ($zip_filename =~ /(BICDir_(?:Increment|All)_(\d\d\d\d)(\d\d)(\d\d)\.zip)$/) {
		# Получить имя файла
        $bicdir->{file_name} = $1;
		# Получить дату файла
        $bicdir->{file_date} = "$2-$3-$4";
    } else {
		# Вернуть ошибку
        return (undef, 'Failed to parse zip file name');
    }

    my $info_data;
	# Прочитать файл .info
    eval {
		CyberFT::Utils::read_file($info_filename, \$info_data);
	};
	# Если возникал ошибка
    if ($@ || !defined $info_data) {
		# Вернуть ошибку
        return (undef, 'Failed to read info file');
    }
	# Шаблоны информационных полей
    my %info_fields = (
        'version'      => qr/^\d+\.\d+$/,
        'encoding'     => qr/^\S+$/,
        'md5_sum'      => qr/^[0-9a-f]{32}$/,
        'num_records'  => qr/^\d+$/,
        'created_at'   => qr/^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d$/,
    );
	# Перебрать шаблоны
    for my $key (keys %info_fields) {
        my $found = 0;
		# Если ключ найден
        if ($info_data =~ /^$key=(\S+)/m) {
            my $val = $1;
			# Если значение ключа совпадает с шаблоном
            if ($val =~ $info_fields{$key}) {
				# Поместить ключ и значение в bicdir
                $bicdir->{$key} = $val;
                $found = 1;
            }
        }
		# Вернуть ошибку
        return (undef, "Info key '$key' not found") unless ($found);
    }

    my $zip_data;
	# Прочитать зип-файл
    eval {
		CyberFT::Utils::read_file($zip_filename, \$zip_data);
	};
	# Если возникла ошибка
    if ($@ || !defined $zip_data) {
		# Вернуть ошибку
        return (undef, 'Failed to read zip file');
    }
	# Закодировать данные в base64
    $bicdir->{data_base64} = MIME::Base64::encode($zip_data);
	# Вернуть результат
    return ($bicdir, undef);
}

# Метод обрабатывает документ с обновлениями справочника участников
sub process_bicdir {
	# Получить входные параметры
    my ($self, $msg_body, $msg_file, $envelope) = @_;
	# Получить поля сообщения из конверта
    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};

    # Проверить, что обновление пришло с родительского процессинга
    my $sys_params = $self->{db}->get_sys_params();
	# Получить системный параметр родительского процессинга
    my $parent_processing = $sys_params->{PARENT_PROCESSING};
	# Если отправитель это не родительский процессинг
    if ($sender_id ne $parent_processing) {
		# Залогировать предупреждение
        $self->log('warning', "BICDir import failed: Sender is not parent processing ($parent_processing)");
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_IMPORT_BICDIR, $doc_id, 'Sender is not parent processing', undef, $sender_id, $envelope->{ReceiverId}, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_IMPORT_BICDIR, CyberFT::Errors::desc(ERR_IMPORT_BICDIR));
        return;
    }

    # Распарсить обновление
    my $parsed = CyberFT::Envelope::parse_bicdir(xml_string => $msg_body, xml_file => $msg_file);
	# Если результат содержит ошибку
    if ($parsed->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', 'BICDir envelope parse failed: ' . $parsed->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_ENVELOPE_PARSE, $doc_id, 'BICDirectoryUpdate parsing failed', undef, $sender_id, $envelope->{ReceiverId}, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE));
        return;
    }

    # Определить тип обновления
    my $bicdir = $parsed->{BICDir};
    my $type;
	# Полное
    if (defined $bicdir->{FullUpdate}) {
        $type = 'all';
    }
	# Инкрементальное
    elsif (defined $bicdir->{IncrementUpdates}) {
        $type = 'increment';
    }
    else {
		# Залогировать предупреждение
        $self->log('warning', 'BICDir import failed: Unknown BICDir envelope type');
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_ENVELOPE_PARSE, $doc_id, 'Unknown BICDir envelope type', undef, $sender_id, $envelope->{ReceiverId}, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_ENVELOPE_PARSE, CyberFT::Errors::desc(ERR_ENVELOPE_PARSE));
        return;
    }
	# Залогировать сервисное сообщение
    $self->log('info', "Starting BICDir update (type=$type)");

    # Распаковаь во временную папку
    my ($tmpdir, $files, $err) = $self->unpack_bicdir($envelope, $type, $bicdir);
	# Если взникал ошибка
    if (defined $err) {
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_IMPORT_BICDIR, $doc_id, $err, undef, $sender_id, $envelope->{ReceiverId}, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_IMPORT_BICDIR, CyberFT::Errors::desc(ERR_IMPORT_BICDIR));
        return;
    }

    # Применить обновление
    $err = $self->import_bicdir($envelope, $type, $files);
	# Если возникла ошибка
    if (defined $err) {
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_IMPORT_BICDIR, $doc_id, $err, undef, $sender_id, $envelope->{ReceiverId}, $doc_type);
		# Изменить статус документа
        $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
		# Послать статус-репорт
        $self->send_status_report($envelope, 'RJCT', ERR_IMPORT_BICDIR, CyberFT::Errors::desc(ERR_IMPORT_BICDIR));
		# Удалить временный каталог с содержимым, если существует
        File::Path::rmtree($tmpdir) if (-d $tmpdir);
        return;
    }
	# Удалить временный каталог с содержимым, если существует
    File::Path::rmtree($tmpdir) if (-d $tmpdir);
	# Изменить статус документа
    $self->change_status($envelope, 17); # Доставлен получателю
	# Послать статус-репорт
    $self->send_status_report($envelope, 'ACDC', 0, '');
}

# Распаковка файлов с обновениями справочника участников.
sub unpack_bicdir {
	# Получить входные параметры
    my ($self, $envelope, $type, $bicdir) = @_;
    my $doc_id = $envelope->{DocId};

    my $tmpdir = CyberFT::Utils::temp_filename($self->{config}->{temp_dir}, 'processor_bicdir');
    my $dir_ok = mkdir($tmpdir);
    unless ($dir_ok) {
		# Залогировать ошибку
        $self->log('error', "Failed to create temporary directory ($tmpdir): $!");
        return (undef, undef, 'Failed to create temporary directory');
    }
	# Залогировать сервисное сообщение
    $self->log('info', "Temporary directory for BICDir: $tmpdir");

    my $files = [];
    my $updates;
	# Если параметр типа инкрементальный
    if ($type eq 'increment') {
		# получить обновления 
        $updates = $bicdir->{IncrementUpdates};
    } else {
        $updates = [$bicdir->{FullUpdate}];
    }

    for my $upd (@$updates) {
        my ($filepath, $filename, $date, $err) = $self->unpack_bicdir_file($tmpdir, $upd);
        if ($err) {
			# Залогировать предупреждение
            $self->log('warning', 'Failed to unpack BICDir file: ' . $upd->{Filename} . ": $err");
            File::Path::rmtree($tmpdir) if (-d $tmpdir);
            return (undef, undef, 'Failed to unpack BICDir file');
        }

        my $timestamp;
        if ($type eq 'increment') {
            my @next_day = Date::Calc::Add_Delta_YMD(@$date, 0, 0, 1);
            $timestamp = sprintf('%04d-%02d-%02d 00:00:00', @next_day);
        } else {
            if ($upd->{LastUpdateDate} =~ /(\d\d\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)/){
                $timestamp = sprintf('%04d-%02d-%02d %02d:%02d:%02d', $1, $2, $3, $4, $5, $6);
            }
        }

        my $cnt = $upd->{ReqCount};

        push @$files, {filepath => $filepath, filename => $filename, date => $date, timestamp => $timestamp, cnt => $cnt};
    }

    $files = [sort {$a->{filename} cmp $b->{filename}} @$files];
    for my $f (@$files) {
		# Залогировать сервисное сообщение
        $self->log('info', 'Extracted from BICDir archive: ' . dumper($f));
    }

    return ($tmpdir, $files, undef);
}

# Распаковка файла с обновлением справочника участников.
sub unpack_bicdir_file {
	# Получить входные параметры
    my ($self, $tmpdir, $upd) = @_;

    my $filename_zip = $upd->{Filename};
    my ($filename, $date);
    if ($filename_zip =~ /^(BICDir_(?:Increment|All)_(\d\d\d\d)(\d\d)(\d\d))\.zip$/) {
        $filename = $1 . '.csv';
        $date = [$2, $3, $4];
    } else {
        return (undef, undef, undef, "Bad zip file name: $filename_zip");
    }

    unless (Date::Calc::check_date(@$date)) {
        return (undef, undef, undef, "Bad zip date: $filename_zip");
    }

    my $zip_data = MIME::Base64::decode($upd->{RawData});
    open(my $fh, '<', \$zip_data);
    my $zip = Archive::Zip->new();
    my $status = $zip->readFromFileHandle($fh);
    if ($zip->readFromFileHandle($fh) != AZ_OK) {
        return (undef, undef, undef, "Failed to read zip file: $filename_zip");
    }

    my $filepath = $tmpdir . '/' . $filename;
    if ($zip->extractMember($filename, $filepath) != AZ_OK) {
        return (undef, undef, undef, "Failed to extract member $filename from zip file: $filename_zip");
    }

    return ($filepath, $filename, $date, undef);
}

# Импорт файлов обновления справочника участников.
sub import_bicdir {
	# Получить входные параметры
    my ($self, $envelope, $type, $files) = @_;
    my $doc_id = $envelope->{DocId};

    # Проверка, что не пропущена какая-либо дата в инкрементальных обновлениях.
    if ($type eq 'increment') {
        my $prev_date;
        for my $file (@$files) {
            if (defined $prev_date) {
                my @must_be_date = Date::Calc::Add_Delta_YMD(@$prev_date, 0, 0, 1);
                my @cur_date = @{$file->{date}};
                if (Date::Calc::Date_to_Days(@cur_date) != Date::Calc::Date_to_Days(@must_be_date)) {
                    my $errstr = sprintf('Missing increment BICDir date: expected %04d-%02d-%02d, got %04d-%02d-%02d', @must_be_date, @cur_date);
					# Залогировать предупреждение
                    $self->log('warning', $errstr);
                    return $errstr;
                }
            }
            $prev_date = $file->{date};
        }
    }

    # Последовательно импортируем файлы обновления.
    for my $file (@$files) {
        my $err = $self->import_bicdir_file($envelope, $type, $file);
        if (defined $err) {
            return $err;
        }
    }

    return undef;
}

# Импорт одного файла обновления справочника участников.
sub import_bicdir_file {
	# Получить входные параметры
    my ($self, $envelope, $type, $file) = @_;
    my $doc_id = $envelope->{DocId};

    my $source_processing = $envelope->{SenderId};
    $source_processing =~ s/^(.{8}).(.{3})$/$1$2/;
	# Залогировать сервисное сообщение
    $self->log('info', 'Starting BICDir member import: ' . $file->{filename});
    my $res = $self->{db}->import_start_member_import({
        RequestType => ($type eq 'increment' ? 1 : 2),
        Source      => $source_processing,
        FileName    => $file->{filename},
        ListDate    => sprintf('%04d-%02d-%02d', @{$file->{date}}),
        UnloadDate  => $file->{timestamp},
        Cnt         => $file->{cnt},
    });
    if ($res->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to start BICDir member import: ' . $res->{ErrMsg});
        return 'Failed to start BICDir member import';
    }
    my $import_id = $res->{Import};

    my $opened = open(my $f, '<', $file->{filepath});
    if (!$opened) {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to open BICDir CSV file: ' . $file->{filename} . ": $!");
        return 'Failed to open BICDir CSV file';
    }

    my $line_num = 0;
    my $load_counter = 0;
    my $converter = Text::Iconv->new('windows-1251', 'utf-8');
    while (my $line = <$f>) {
        $line_num++;
        next if ($line_num == 1);

        chomp($line);
        $line = Encode::decode_utf8($converter->convert($line));

        my @values = map { defined($_) && $_ ne '' ? $_ : undef } split(/;/, $line);

        my $record = {
            Import          => $import_id,
            ExpId           => $values[0],
            SwiftCode       => $values[1],
            ParentSwiftCode => $values[2],
            MemberType      => $values[3],
            MemberName      => $values[4],
            EngName         => $values[5],
            IsBank          => $values[6],
            Status          => $values[7],
            Block           => $values[8],
            CntrCode2       => $values[9],
            CityName        => $values[10],
            ValiFrom        => $values[11],
            ValiTo          => $values[12],
            WebSite         => $values[13],
            MemberPhone     => $values[14],
            Lang            => $values[15],
        };

        $res = $self->{db}->import_load_member_record($record);

        if ($res->{Result} ne '0') {
			# Залогировать предупреждение
            $self->log('warning', 'Failed load BICDir member record: ' . $res->{ErrMsg});
            return 'Failed load BICDir member record';
        }

        $load_counter++;
    }
	# Залогировать сервисное сообщение
    $self->log('info', 'Successfully loaded BICDir records: ' . $load_counter);

    close($f);
	# Залогировать сервисное сообщение
    $self->log('info', 'Processing BICDir import: ' . $file->{filename});
    $res = $self->{db}->import_process_import({
        Import => $import_id,
    });
    if ($res->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to process BICDir import: ' . $res->{ErrMsg});
        return 'Failed to process BICDir import';
    }
	# Залогировать сервисное сообщение
    $self->log('info', 'Processed BICDir import: ' . $file->{filename} . ': ' . dumper($res));

    # Отправка отчета об обновлении справочника.
    $self->send_bicdir_import_mail($res);

    return undef;
}

# Отправка отчета по результатам импорта обновлений справочника участников.
sub send_bicdir_import_mail {
	# Получить входные параметры
    my ($self, $result) = @_;

    my $email_from = $self->{config}->{sys_email};
    my $email_to = $result->{Mail};

    if ($email_to !~ /@/) {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to send BICDir import email: Bad system Mail setting');
        return;
    }

    my $subject = 'Обновление справочника участников CyberFT (' . $self->{config}->{sys_id} . ')';
    my $subject_rfc2047 = '=?UTF-8?B?'. MIME::Base64::encode(Encode::encode_utf8($subject), '') . '?=';

    my $status;
    if ($result->{Status} == 1) {
        $status = 'Импорт создан';
    }
    elsif ($result->{Status} == 2) {
        $status = 'Импорт завершен';
    }
    elsif ($result->{Status} == 3) {
        $status = 'Импорт завершен с ошибкой: ' . $result->{ErrInfo};
    }
    elsif ($result->{Status} == 10) {
        $status = 'Импорт прерван';
    }
    else {
        $status = 'Статус неизвестен';
    }

    my $text;
    $text .= 'Имя загруженного файла: ' . $result->{FileName} . "\n";
    $text .= 'Количество обработанных записей: ' . $result->{ProcessedCnt} . "\n";
    $text .= 'Количество новых записей: ' . $result->{AddCnt} . "\n";
    $text .= 'Количество удаленных записей: ' . $result->{DelCnt} . "\n";
    $text .= 'Количество предупреждений: ' . $result->{WarnCnt} . "\n";
    $text .= 'Дата и время загрузки в БД: ' . $result->{ProcessedDate} . "\n";
    $text .= 'Статус: ' . $status . "\n";

    my $sent;
    eval {
        my $msg = MIME::Lite->new(
            From     => $email_from,
            To       => $email_to,
            Subject  => $subject_rfc2047,
            Type     => 'text/plain',
            Data     => Encode::encode_utf8($text),
        );
        $msg->attr('content-type' => 'text/plain');
        $msg->attr('content-type.charset' => 'utf-8');
        $sent = $self->{config}{smtp_host} ? $msg->send('smtp', $self->{config}{smtp_host}) : $msg->send();
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to send BICDir import email: ' . $err);
        return;
    }
    if (!$sent) {
		# Залогировать предупреждение
        $self->log('warning', 'Failed to send BICDir import email');
        return;
    }
	# Залогировать сервисное сообщение
    $self->log('info', 'BICDir import email sent (' . $email_to . ')');
    return;
}

# Обработка отчета о статусе.
sub process_status_report {
	# Получить входные параметры
    my ($self, $msg_body, $msg_file, $envelope) = @_;

    my $doc_id = $envelope->{DocId};
    my $sender_id = $envelope->{SenderId};
    my $ref_doc_id = $envelope->{StatusReport_RefDocId};
    my $status_code = $envelope->{StatusReport_StatusCode};

    # Залогировать сервисное сообщение
    $self->log('info', "StatusReport recieved from $sender_id: RefDocId=$ref_doc_id, StatusCode=$status_code");
}

# Обработка документа неизвестного типа.
sub process_unknown {
	# Получить входные параметры
    my ($self, $msg_body, $msg_file, $envelope) = @_;

    my $doc_id = $envelope->{DocId};
    my $doc_type = $envelope->{DocType};
    my $sender_id = $envelope->{SenderId};
    my $receiver_id = $envelope->{ReceiverId};
	# Залогировать предупреждение
    $self->log('warning', "Cannot process DocType: $doc_type");
	# Сохранить ошибку в базе данных
    $self->save_error(ERR_DOCTYPE_PROCESS, $doc_id, $doc_type, undef, $sender_id, $receiver_id, $doc_type);
	# Изменить статус документа
    $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
	# Послать статус-репорт
    $self->send_status_report($envelope, 'RJCT', ERR_DOCTYPE_PROCESS, CyberFT::Errors::desc(ERR_DOCTYPE_PROCESS));
}

# Метод изменяет статус обрабатываемого документа
sub change_status {
	# Получить входные параметры
    my ($self, $envelope, $new_status) = @_;
	# Получить поля заголовка из конверта
    my $doc_id = $envelope->{DocId};
    my $sender_id = $envelope->{SenderId};
    my $doc_type = $envelope->{DocType};
    my $receiver_id = $envelope->{ReceiverId};
	# Если документ типа ACK, вернуться
    if ($doc_type eq 'CFTAck') {
        return;
    }
	# Сохранить статус сообзения в базу данных
    my $r = $self->save_message_status_to_db(doc_id => $doc_id, sender_id => $sender_id, status => $new_status, 'doc_type' => $doc_type);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать предупреждение
        $self->log('warning', "Saving status error: " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
		# Сохранить ошибку в базе данных
        $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
    }
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
	# Получить входные параметры
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

    # Поместить отчёт в стандартный xml-конверт CyberFT
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

# Метод меняет статус сообщения и отправляет StatusReport начальному отправителю
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
	# Изменить статус документа
    $self->change_status($envelope, 18); # Доставлен получателю с ошибкой
	# Послать статус-репорт
    $self->send_status_report($envelope, 'RJCT', $err_code, $err_msg);
}

# Метод сохраняет сообщение в базу данных.
sub save_message_to_db {
    my $self = shift;
	# Получить список входных параметров
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

    # Если возникла ошибка
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

    my $another_segment = $result->{AnotherSegment};
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => "", AnotherSegment => $another_segment, Message => $result->{Message}};
}

# Метод сохраняет статус сообщения в базу данных. Расшифровка статусов:
#   15 - Доставлен следующему узлу
#   17 - Доставлен получателю
#   18 - Доставлен получателю с ошибкой
#   19 - Не доставлен
sub save_message_status_to_db {
    my $self = shift;
	# Получить список входных параметров
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

    # Если возникла ошибка
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        if ($result->{Result} eq '1') {
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        }
        else {
            # Залогировать нестандартную ошибку
            $self->log('error', 'save_message_status_to_db: ' . $p{doc_id} .
                       ': set_message_status error: ' . $result->{ErrCode} . ': ' . $result->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_DATABASE, $p{doc_id}, $result->{ErrMsg}, undef, $p{sender_id}, $p{receiver_id}, $p{doc_type});
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
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
		# Если был установлен результат с ошибкой
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
	# Вернуть успешный результат
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

    # Если возникла ошибка
    if ($result->{Result} ne '0') {
        my ($err_code, $err_msg);
        if ($result->{Result} eq '1') {
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


# После возникновения необработанной ошибки во время обработки фрейма нужно вызвать recover
# Метод разрывает и заново устанавливает соединение с брокером.
# Также проверяется соединение с базой. Если его нет, то оно восстанавливается.
sub recover {
    my $self = shift;
	# Если есть соединение с брокером
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
	# Если есть соединение с брокером
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