# Класс форвардера для перенаправления сообщений

package CyberFT::Forwarder;

use strict;
use utf8;
use Data::Dumper;
use Data::UUID ();
use MIME::Base64 ();
use Net::Stomp;
use Convert::PEM ();
use Digest::MD5 ();
use Encode ();
use Time::HiRes ();
use Crypt::OpenSSL::X509 ();
use File::Copy ();
use xmldsig ();

use CyberFT::Broker;
use CyberFT::Database;
use CyberFT::Envelope;
use CyberFT::Errors;

# Импорт библиотечных методов
use CyberFT::Utils qw(
    escape_crlf
    remove_crlf
    read_file
    write_file
    dumper
    temp_filename
    timestamp_hires
    gen_timestamps
);

# Максимальный размер документа в памяти
my $MAX_IN_MEMORY_DOC_SIZE = 4 * 1024 * 1024;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
}

# Метод инициализирует форвардер
# Обязательные параметры:
#     sys_id, broker_host, broker_port, broker_username, broker_password,
#     db_data_source, db_username, db_password, log_func.
# Здесь параметр log_func - функция логирования. В нее будут передаваться два параметра:
#     уровень ("info", "warning", "error", "debug") и сообщение для записи в лог.
sub init {
    my $self = shift;
    # Получить список входных параметров
    my %params = @_;
    # Конфиг заполняется входными параметрами
    $self->{config} = \%params;

    # Параметры, которые должны присутствовать:
    my @required_params = qw(
        sys_id
        sys_certificate_file
        sys_private_key_file
        sys_private_key_password
        broker_host
        broker_port
        broker_username
        broker_password
        broker_spool_dir
        broker_max_body_size
        broker_chunk_size
        broker_chunk_timeout
        broker_cftcp_bin
        db_data_source
        db_username
        db_password
        temp_dir
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
    # Залогировать сервисное сообщение
    $self->log('info', 'Initialization');
    $self->log('info', 'Self Id: ' . $self->{config}->{sys_id});

    # Подключиться к базе данных
    my $r = $self->connect_database();
    # Если результат содержит ошибку
    if ($r->{Result} ne '0') {
        # Залогировать ошибку
        $self->log('error', 'Initialization failed: Database connection error: ' . $r->{ErrMsg});
        return $r;
    }

    # Подключиться к брокеру сообщений
    my $r = $self->connect_broker();
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Залогировать ошибку
        $self->log('error', 'Initialization failed: Mesasge broker error: ' . $r->{ErrMsg});
        return $r;
    }

	# Залогировать сервисное сообщение
    # Получим системный ключ и сертификат для подписи ответных сообщений
    $self->log('info', 'Reading signing keys');
    eval {
        $self->load_system_private_key();
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

# Соединение с базой данных.
# В случае ошибки пытается переподключаться через определенный интервал времени.
sub connect_database {
    my $self = shift;
	# Получить список входных параметров
    my %params = @_;
    my $retry_count = $params{retry_count}; # если не задано - будет пытаться бесконечно.
	# Залогировать сервисное сообщение
    $self->log('info', 'Connecting to the database: ' . $self->{config}->{db_data_source});
    $self->{db} = CyberFT::Database::new_instance($self->{config});

    my $retry_counter = 0;
    my $interval = 5; # 5 секунд
    my $error_message;

    while (1) {
        my $db_conn_res = $self->{db}->connect();
        if ($db_conn_res->{Result} eq '0') {
			# Вернуть успешный результат
            return {Result => 0, ErrCode => 0, ErrMsg => ''};
        }
        elsif (!defined($retry_count) || $retry_counter < $retry_count) {
			# Залогировать ошибку
            $self->log('error', 'Database connection error: ' . $db_conn_res->{ErrMsg});
            $self->log('error', 'Retrying database connection after: ' . $interval . 's');
            $retry_counter += 1;
            sleep($interval);
            next;
        }
        $error_message = $db_conn_res->{ErrMsg};
        last;
    }
	# Вернуть результат с ошибкой
    return {Result => 1, ErrCode => 10, ErrMsg => $error_message};
}

# Проверка соединения с базой и переподключение при необходимости.
# Проверка выполняется через определенные промежутки времени или если выставлен флаг db_check_needed.
sub check_database_connection {
    my $self = shift;
    my $interval = 1 * 60;
    if (!defined($self->{db_last_checked}) || time() - $self->{db_last_checked} > $interval) {
        $self->{db_check_needed} = 1;
    }
    if ($self->{db_check_needed}) {
        unless (defined($self->{db}) && $self->{db}->ping()) {
			# Залогировать ошибку
            $self->log('error', 'Database connection lost');
            $self->connect_database();
        }
        $self->{db_check_needed} = 0;
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

# Главный цикл обработки сообщений.
sub process_loop {
    my $self = shift;
    my $done = shift; # ссылка на переменную-флаг для остановки цикла.
	# Пока цикл не остановлен
    while (!$$done) {
        eval {
            my $r = $self->process_step(1);
			# Если результат содержит ошибку
            if ($r->{Result} ne '0') {
                $self->log("warning", "process_loop: process_step error: " . $r->{ErrMsg});
            }
            $self->{log_prefix} = undef;
        };
		# Если возникла ошибка
        if (my $err = $@) {
            $self->log("error", "process_loop: process_step died: " . $err);
			# Сохранить ошибку
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

# Метод получает и обрабатывает одно исходящее сообщение из базы
sub process_step {
    my $self = shift;
	# Параметр таймаута
    my $timeout = shift;

    $self->{log_prefix} = undef;

    # Проверить и восстановить соединение с базой при необходимости
    $self->check_database_connection();
	# Временный файл
    my $msg_file = temp_filename($self->{config}->{temp_dir}, 'forwarder');

    my $r = $self->get_next_message_from_db($msg_file);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_GET_UNSENT);
		# Пауза
        sleep($timeout);
		# Вернуть результат
        return $r;
    }
	# Если результат не содержит сообщения
    if ($r->{Data}->{Message} == 0) {
		# Пауза
        sleep($timeout);
		# Вернуть результат, что нет новых сообщений
        return {Result => 0, ErrCode => 0, ErrMsg => 'No new messages'};
    }
	# Залогировать сервисное сообщение
    $self->log('info', 'got new message');
	# Получить из результата сообщение, ид отправителя и ид документа
    my $msg_data = $r->{Data};
    my $sender_id = $msg_data->{SenderSwift};
    my $doc_id = $msg_data->{SenderMsgCode};

	# Установить префикс логирования как ид отправителя и ид документа
    $self->{log_prefix} = "[$sender_id-$doc_id] ";
	# Получить время
    my $timestamp = timestamp_hires();
	# Залогировать сервисное сообщение
    $self->log('info', "In: Timestamp=$timestamp; Message=" . $msg_data->{Message});

    my ($msg_body, $msg_len, $inmemory);
	# Если сообщение содержит тело
    if (defined $msg_data->{MsgBody}) {
		# Получить тело
        $msg_body = $msg_data->{MsgBody};
		# Удалить тело из данных сообщения
        delete($msg_data->{MsgBody});
		# Поставить флаги обработки в памяти
        $msg_file = undef;
        $inmemory = 1;
		# Получить длину сообщения
        $msg_len = length($msg_body);
    } else {
		# Залогировать сервисное сообщение
        $self->log('info', 'Document saved to: ' . $msg_file);
		# Отключить флаг обработки в памяти
        $inmemory = 0;
		# Получить длину файла
        $msg_len = -s $msg_file;
    }
	# Залогировать сервисное сообщение
    $self->log('info', "Document size: $msg_len; In-memory processing: $inmemory");

    # Обработать сообщение с параметрами
    $self->process_message(msg_body => $msg_body, msg_file => $msg_file, msg_len => $msg_len, msg_data => $msg_data);

    # Удалить временный файл
    if (defined $msg_file && -f $msg_file) {
        unlink($msg_file);
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => 'OK'};
}

# Метод обрабатывает отдельное сообщение (xml-конверт)
sub process_message {
	# Входные параметры
    my ($self, %opts) = @_;
	# Получить параметры сообщения
    my $msg_body = $opts{msg_body};
    my $msg_file = $opts{msg_file};
    my $msg_len = $opts{msg_len};
    my $msg_data = $opts{msg_data};

    my $doc_id = $msg_data->{SenderMsgCode};
    my $sender_id = $msg_data->{SenderSwift};
    my $receiver_id = $msg_data->{ReceiverSwift};
    my $doc_type = $msg_data->{MsgCode};
    my $next_id = $msg_data->{NextSwift};
    my $another_segment = $msg_data->{AnotherSegment};
    my $time_limit = $msg_data->{TimeLimit};
	# Залогировать сервисное сообщение
    $self->log('info', 'Document db info: ' . remove_crlf(dumper($msg_data)));
	# Если время сообщения просрочено
    if ($msg_data->{TimeExired}) {
		# Получить лимит времени
        my $time_limit = $msg_data->{TimeLimit};
		# Залогировать предупреждение
        $self->log('warning', "Time Limit expired (TimeLimit='$time_limit')");
		# Сохранить ошибку
        $self->save_error(ERR_TIMELIMIT_EXPIRED, $doc_id, $time_limit, undef, $sender_id, $receiver_id, $doc_type);
		# Послать статус-репорт
        $self->send_status_report($sender_id, $doc_id, 'RJCT', ERR_TIMELIMIT_EXPIRED, CyberFT::Errors::desc(ERR_TIMELIMIT_EXPIRED));

        # Сохранить статус документа в базе данных
        my $r = $self->save_message_status_to_db(
            doc_id     => $doc_id,
            sender_id  => $sender_id,
            status     => 19,
            is_error   => 1,
            error_code => ERR_TIMELIMIT_EXPIRED,
            error_desc => CyberFT::Errors::desc(ERR_TIMELIMIT_EXPIRED),
        );
		# Если результат содержит ошибку
        if ($r->{Result} ne '0') {
			# Залогировать предупреждение
            $self->log('warning', 'Saving status error: ' . $r->{ErrCode} . ': ' . $r->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        }
		# Вернуться
        return;
    }
	# Получить настройку максимального размера сообщения
    my $max_body_size = $self->{config}->{broker_max_body_size};
	# Результат отправки
    my $sndres;
	# Если в другой сегмент
    if ($another_segment) {
		# Получить адрес получателя
        my $addr = $msg_data->{RcvLoginAddr};
		# Если сообщение не превышает максимального размера
        if ($msg_len <= $max_body_size) {
			# Залогировать сервисное сообщение
            $self->log('info', "Sending to NextId=$next_id (remote, small)");
			# Послать малое сообщение
            $sndres = $self->send_remote_small(
                msg_body    => $msg_body,
                msg_file    => $msg_file,
                doc_id      => $doc_id,
                addr        => $addr,
                sender_id   => $sender_id,
                receiver_id => $receiver_id,
                doc_type    => $doc_type,
            );
        } else {
			# Залогировать сервисное сообщение
            $self->log('info', "Sending to NextId=$next_id (remote, big)");
			# Послать большое сообщение
            $sndres = $self->send_remote_big(
                msg_body    => $msg_body,
                msg_file    => $msg_file,
                doc_id      => $doc_id,
                addr        => $addr,
                sender_id   => $sender_id,
                receiver_id => $receiver_id,
                doc_type    => $doc_type,
            );
        }
    } else {
		# Длина очереди приёма
        my $qlen = $msg_data->{RcvQueueLen};
        my $qlen_str = (defined $qlen) ? $qlen : 'undefined';
		# Если размер сообщения меньше максимального
        if ($msg_len <= $max_body_size) {
			# Залогировать сервисное сообщение
            $self->log('info', "Sending to NextId=$next_id (local, small, qlen=$qlen_str)");
            $sndres = $self->send_local_small(
                msg_body    => $msg_body,
                msg_file    => $msg_file,
                doc_id      => $doc_id,
                next_id     => $next_id,
                qlen        => $qlen,
                sender_id   => $sender_id,
                receiver_id => $receiver_id,
                doc_type    => $doc_type,
            );
        } else {
			# Залогировать сервисное сообщение
            $self->log('info', "Sending to NextId=$next_id (local, big, qlen=$qlen_str)");
            if ($msg_data->{RcvFrgReady}) {
                $sndres = $self->send_local_big(
                    msg_body    => $msg_body,
                    msg_file    => $msg_file,
                    doc_id      => $doc_id,
                    next_id     => $next_id,
                    qlen        => $qlen,
                    sender_id   => $sender_id,
                    receiver_id => $receiver_id,
                    doc_type    => $doc_type,
                );
            } else {
                # Получатель не поддерживает получение больших документов.
				# Сохранить ошибку
                $self->save_error(ERR_RECV_FRAGMENT_SUPPORT, $doc_id, $next_id, undef, $sender_id, $receiver_id, $doc_type);
				# Заполнить результат
                $sndres = {Result => 2, ErrCode => ERR_RECV_FRAGMENT_SUPPORT, ErrMsg => CyberFT::Errors::desc(ERR_RECV_FRAGMENT_SUPPORT)};
            }
        }
    }
	# Если результат успешный
    if ($sndres->{Result} eq '0') {
        # Получить время
        my $timestamp = timestamp_hires();
		# Залогировать сервисное сообщение
        $self->log('info', "Successfully sent: Timestamp=$timestamp");
        # Сохранить статус документа в базе данных
        my $r = $self->save_message_status_to_db(doc_id => $doc_id, sender_id => $sender_id, status => 33);
		# Если результат содержит ошибку
        if ($r->{Result} ne '0') {
			# Залогировать предупреждение
            $self->log('warning', "Saving status error: " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        }
    } elsif ($sndres->{Result} eq '2') {
        # Невозможно отправить
		# Залогировать предупреждение
        $self->log('warning', "Cannot send: " . $sndres->{ErrCode} . ': ' . $sndres->{ErrMsg});
		# Послать статус-репорт
        $self->send_status_report($sender_id, $doc_id, 'RJCT', $sndres->{ErrCode}, $sndres->{ErrMsg});
        # Сохранить статус документа в базе данных
        my $r = $self->save_message_status_to_db(
            doc_id     => $doc_id,
            sender_id  => $sender_id,
            status     => 19,
            is_error   => 1,
            error_code => $sndres->{ErrCode},
            error_desc => $sndres->{ErrMsg},
        );
		# Если результат содержит ошибку
        if ($r->{Result} ne '0') {
			# Залогировать предупреждение
            $self->log('warning', "Saving status error: " . $r->{ErrCode} . ': ' . $r->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        }
    }
	# Ошибка отправки
    else {
		# Залогировать предупреждение
        $self->log('warning', 'Send error: ' . $sndres->{ErrCode} . ': ' . $sndres->{ErrMsg});
        # Сохранить статус документа в базе данных
        my $r = $self->save_message_status_to_db(doc_id => $doc_id, sender_id => $sender_id, status => 37);
		# Если результат содержит ошибку
        if ($r->{Result} ne '0') {
			# Залогировать предупреждение
            $self->log('warning', 'Saving status error: ' . $r->{ErrCode} . ': ' . $r->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
        }
    }
}

# Метод посылает малое сообщение удалённому получателю
sub send_remote_small {
	# Получить входные параметры
    my ($self, %opts) = @_;
	# Получить параметры сообщения	
    my $msg_body = $opts{msg_body};
    my $msg_file = $opts{msg_file};
    my $doc_id = $opts{doc_id};
    my $addr = $opts{addr};
    my $sender_id = $opts{sender_id};
    my $receiver_id = $opts{receiver_id};
    my $doc_type = $opts{doc_type};
	# Разделить адрес на части
    my ($host, $port, $pass) = split(':', $addr);
	# Создать объект брокера
    my $broker = CyberFT::Broker->new;
	# Открыть соединение с брокером
    my $r = $broker->connect(
        $host,
        $port,
        $self->{config}->{sys_id},
        $pass,
        $self->{config}->{log_func},
    );
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_REMOTE, $doc_id, "Ошибка подключения к брокеру сообщений: $host:$port", undef, $sender_id, $receiver_id, $doc_type);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Составить заголовки
    my $headers = {
        'doc_id'    => $doc_id,
        'sender_id' => $sender_id,
        'doc_type'  => $doc_type,
    };
	# Если нет тела письма
    unless (defined $msg_body) {
		# Прочитать тело письма из файла
        eval {
            read_file($msg_file, \$msg_body);
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Залогировать ошибку
            $self->log('error', "send_remote_small: temp file read error ($msg_file): $err");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Temp file read error"};
        }
    }
	# Послать сообщение в очередь INPUT
    my $r = $broker->send_frame('INPUT', $msg_body, $headers);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_REMOTE, $doc_id, $r->{ErrMsg}, undef, $sender_id, $receiver_id, $doc_type);
		# Закрыть соединение с брокером
        $broker->disconnect;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Закрыть соединение с брокером
    $broker->disconnect;
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Метод посылает большое сообщение удалённому получателю
sub send_remote_big {
	# Получить входные параметры
    my ($self, %opts) = @_;
	# Получить параметры сообщения
    my $msg_body = $opts{msg_body};
    my $msg_file = $opts{msg_file};
    my $doc_id = $opts{doc_id};
    my $addr = $opts{addr};
    my $sender_id = $opts{sender_id};
    my $receiver_id = $opts{receiver_id};
    my $doc_type = $opts{doc_type};
	# Разбить адрес на части
    my ($host, $port, $pass) = split(':', $addr);
    my $login = $self->{config}->{sys_id};
	# Получить ид файла
    my $file_id = $sender_id . '-' . $doc_id;
	# Путь к программе cftcp
    my $cftcp = $self->{config}->{broker_cftcp_bin};
    my $timeout = $self->{config}->{broker_chunk_timeout};
	# Размер фрагмента
    my $csize = $self->{config}->{broker_chunk_size};

    # Для того, чтобы cftcp не начинал каждый раз закачку файла с нуля (если с первого раза не получилось),
    # будем сохранять один и тот же исходящий документ всегда с одинаковым именем, перед запуском cftcp.
	# Получить временную папку из конфига
    my $temp_dir = $self->{config}->{temp_dir};
	# Очистить последний "/"
    $temp_dir =~ s|\/$||;
	# Составить путь к выходному файлу
    my $output_file = $temp_dir . '/' . 'forwarder_out_' . $file_id . '.blob';
	# Если задано тело сообщения
    if (defined $msg_body) {
		# Залогировать сервисное сообщение
        $self->log('info', "Saving output file to: $output_file");
		# Записать файл
        eval {
            write_file($output_file, \$msg_body);
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Залогировать ошибку
            $self->log('error', "send_remote_big: output file save error ($output_file): $err");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Output file save error"};
        }
    } else {
		# Залогировать сервисное сообщение
        $self->log('info', "Moving output file to: $output_file");
		# Переместить файл сообщения в выходной файл
		# Если возникла ошибка при перемещении
        unless (File::Copy::move($msg_file, $output_file)) {
			# Залогировать ошибку
            $self->log('error', "send_remote_big: output file move error ($msg_file, $output_file): $!");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Output file move error"};
        }
    }
    # Команда запуска cftcp
    my $cmd = "$cftcp -P $port -T $timeout -C $csize -U $login -v -R $output_file $host:$file_id 2>&1";
    # Залогировать сервисное сообщение
    $self->log('info', "cftcp command: $cmd");
    # Запустить команду и получить результат
    my @output = `echo "$pass" | $cmd`;
    my $ret_code = $? >> 8;
    # Разобрать результат построчно
    for my $line (@output) {
        $line =~ s/[\n\r]+$//;
        # Залогировать сервисное сообщение
        $self->log('info', "cftcp output: $line");
    }
	# Залогировать сервисное сообщение
    $self->log('info', "cftcp ret_code: $ret_code");
	# Удалить выходной файл, если он существует
    unlink($output_file) if (-f $output_file);
	# Если процесс вернул код ошибки
    if ($ret_code != 0) {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_REMOTE, $doc_id, "Код возврата cftcp: $ret_code", undef, $sender_id, $receiver_id, $doc_type);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "Error sending document: cftcp return code: $ret_code"};
    }
	# Создать объект брокера
    my $broker = CyberFT::Broker->new;
	# Установить соединение с брокером
    my $r = $broker->connect(
        $host,
        $port,
        $self->{config}->{sys_id},
        $pass,
        $self->{config}->{log_func},
    );
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_REMOTE, $doc_id, "Ошибка подключения к брокеру сообщений: $host:$port", undef, $sender_id, $receiver_id, $doc_type);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Составить заголовки
    my $headers = {
        'doc_id'    => $doc_id,
        'sender_id' => $sender_id,
        'doc_type'  => $doc_type,
        'file_id'   => $file_id,
    };
	# Послать сообщение в очередь INPUT
    my $r = $broker->send_frame('INPUT', '', $headers);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_REMOTE, $doc_id, $r->{ErrMsg}, undef, $sender_id, $receiver_id, $doc_type);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Метод посылает малое сообщение локальному получателю
sub send_local_small {
	# Получить входные параметры
    my ($self, %opts) = @_;
	# Получить поля сообщения
    my $msg_body = $opts{msg_body};
    my $msg_file = $opts{msg_file};
    my $next_id = $opts{next_id};
    my $qlen = $opts{qlen};
    my $doc_id = $opts{doc_id};
    my $sender_id = $opts{sender_id};
    my $receiver_id = $opts{receiver_id};
    my $doc_type = $opts{doc_type};
	# Составить заголовки
    my $headers = {
        'doc_id'    => $doc_id,
        'sender_id' => $sender_id,
        'doc_type'  => $doc_type,
    };
	# Если опредлелена длина очереди
    if (defined $qlen && $qlen ne '') {
		# Добавить длину очереди в заголовки
        $headers->{'max-num'} = $qlen;
    }
	# Если не задано тело сообщения
    unless (defined $msg_body) {
		# Прочитать тело сообщения из файла
        eval {
            read_file($msg_file, \$msg_body);
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Залогировать ошибку
            $self->log('error', "send_local_small: temp file read error ($msg_file): $err");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Temp file read error"};
        }
    }
	# Послать сообщение в брокер
    my $r = $self->{broker}->send_frame($next_id, $msg_body, $headers);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_LOCAL, $doc_id, $r->{ErrMsg}, undef, $sender_id, $receiver_id, $doc_type);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

# Метод посылает большое сообщение локальному получателю
sub send_local_big {
	# Получить входные параметры
    my ($self, %opts) = @_;
	# Получить поля сообщения
    my $msg_body = $opts{msg_body};
    my $msg_file = $opts{msg_file};
    my $next_id = $opts{next_id};
    my $qlen = $opts{qlen};
    my $doc_id = $opts{doc_id};
    my $sender_id = $opts{sender_id};
    my $receiver_id = $opts{receiver_id};
    my $doc_type = $opts{doc_type};
	# Создать ид файла
    my $file_id = $sender_id . '-' . $doc_id;
	# Получить папку хранилища брокера из конфига
    my $broker_spool_dir = $self->{config}->{broker_spool_dir};
	# Удалить последний "/"
    $broker_spool_dir =~ s|\/$||;
	# Составить путь для выходного файла
    my $output_file = $broker_spool_dir . '/' . $next_id . '-' . $file_id . '.blob';
	# Если задано тело сообщения
    if (defined $msg_body) {
		# Залогировать сервисное сообщение
        $self->log('info', "Saving to spool: $output_file");
		# Записать тело соощения в выходной файл
        eval {
            write_file($output_file, \$msg_body);
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Залогировать ошибку
            $self->log('error', "send_local_big: output file save error ($output_file): $err");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Output file save error"};
        }
    } else {
		# Залогировать сервисное сообщение
        $self->log('info', "Moving to spool: $output_file");
		# Переместить файл сообщения в выходной файл
        unless (File::Copy::move($msg_file, $output_file)) {
			# Залогировать ошибку
            $self->log('error', "send_local_big: output file move error ($msg_file, $output_file): $!");
			# Сохранить ошибку
            $self->save_error(ERR_FILE_ACCESS, $doc_id, undef, undef, $sender_id, $receiver_id, $doc_type);
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Output file move error"};
        }
    }
	# Составить заголовки
    my $headers = {
        'doc_id'    => $doc_id,
        'sender_id' => $sender_id,
        'doc_type'  => $doc_type,
        'file_id'   => $file_id,
    };
	# Если определена длина очереди, добавить её в заголовки
    if (defined $qlen && $qlen ne '') {
        $headers->{'max-num'} = $qlen;
    }
	# Послать сообщение брокеру
    my $r = $self->{broker}->send_frame($next_id, '', $headers);
	# Если результат содержит ошибку
    if ($r->{Result} ne '0') {
		# Сохранить ошибку
        $self->save_error(ERR_MSG_ENQUEUE_LOCAL, $doc_id, $r->{ErrMsg}, undef, $sender_id, $receiver_id, $doc_type);
        unlink($output_file);
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $r->{ErrCode}, ErrMsg => $r->{ErrMsg}};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ""};
}

sub send_status_report {
    my ($self, $sender_id, $doc_id, $status_code, $err_code, $err_msg) = @_;

    my ($rep, $rep_id, $rep_docdate) = $self->gen_status_report(
        $sender_id,
        $doc_id,
        $status_code,
        $err_code,
        $err_msg
    );
    unless (defined $rep) {
        return;
    }

    # Добавим ответ в базу.
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
        return;
    }
	# Залогировать сервисное сообщение
    $self->log('info', "Sent: StatusReport to $sender_id (RefDocId=$doc_id, StatusCode=$status_code) DocId=$rep_id");
}

# Создание подписанного отчета об ошибке обработки сообщения для отправителя (StatusReport).
sub gen_status_report {
    my $self = shift;
    my $to = shift;
    my $doc_id = shift;
    my $status_code = shift;
    my $error_code = shift;
    my $error_message = shift;

    $error_message =~ s/&/&amp;/g;
    $error_message =~ s/</&lt;/g;
    $error_message =~ s/>/&gt;/g;

    my $report_xml = "";
    $report_xml .= q{<StatusReport xmlns="http://cyberft.ru/xsd/cftdata.01">};
    $report_xml .= q{<RefDocId>} . $doc_id . q{</RefDocId>};
    $report_xml .= q{<StatusCode>} . $status_code . q{</StatusCode>};
    $report_xml .= q{<ErrorCode>} . $error_code . q{</ErrorCode>};
    $report_xml .= q{<ErrorDescription>} . $error_message . q{</ErrorDescription>};
    $report_xml .= q{</StatusReport>};

    my ($xml_date, $db_date) = gen_timestamps();

    # Завернем отчет в стандартный xml-конверт CyberFT.
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
        return undef;
    }

    return ($r->{Content}, $r->{DocId}, $db_date);
}

sub get_next_message_from_db {
    my $self = shift;
    my $msg_file = shift;

    my $params = {
        MsgBody_FileName    => $msg_file,
        SmartMsgBodyMaxSize => $MAX_IN_MEMORY_DOC_SIZE,
        Timeout             => ($self->{config}->{unsent_document_db_read_timeout} || 300)
    };

    my $result = $self->{db}->get_next_unsent($params);

    # Если вернулась ошибка:
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        if ($result->{Result} eq '1') {
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        }
        elsif ($result->{ErrCode} eq '-2') { # Timeout
			# Залогировать ошибку
            $self->log('error', "get_next_message_from_db: DB read timeout exceeded");
            $self->{db_check_needed} = 1;

            # Сохраним в базе статус документа "Ошибка постановки в очередь".
            my $doc_id = $result->{SenderMsgCode};
            my $sender_id = $result->{SenderSwift};
            my $receiver_id = $result->{ReceiverSwift};
            my $doc_type = $result->{MsgCode};
            if ($doc_id && $sender_id) {
				# Сохранить статус документа в базе данных
                my $r = $self->save_message_status_to_db(doc_id => $doc_id, sender_id => $sender_id, status => 37);
				# Если результат содержит ошибку
                if ($r->{Result} ne '0') {
					# Залогировать предупреждение
                    $self->log('warning', "Saving status error: ".$r->{ErrCode}.': '.$r->{ErrMsg});
					# Сохранить ошибку
                    $self->save_error(ERR_SAVE_MESSAGE_STATUS, $doc_id, "$sender_id-$doc_id", $r->{ErrMsgDB}, $sender_id, $receiver_id, $doc_type);
                }
            } else {
				# Залогировать ошибку
                $self->log('error', "get_next_message_from_db: empty document id or sender id, will not change status to 37");
            }

            return { Result => 1, ErrCode => ERR_PROCESSING, ErrMsg => CyberFT::Errors::desc(ERR_PROCESSING), ErrMsgDB => 'DB read tiemout exceeded'};
        }
        else {
            # это какая-то нестандартная ошибка
			# Залогировать ошибку
            $self->log('error', 'get_next_message_from_db: get_next_unsent error: '
						. $result->{ErrCode} . ': ' . $result->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_DATABASE);
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            $self->{db_check_needed} = 1;
        }
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg, ErrMsgDB => $err_msg_db};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => "", Data => $result};
}

# Сохранение сообщения в базу данных.
sub save_message_to_db {
    my $self = shift;
    my %p = @_;

    my $params = {
        MsgBody          => $p{msg},
        SenderMsgCode    => $p{doc_id},
        SenderSwift      => $p{sender_id},
        ReceiverSwift    => $p{receiver_id},
        MsgCode          => $p{doc_type},
        MessageLength    => $p{msg_len},
        MessageSum       => $p{msg_sum},
        MessageCnt       => $p{msg_cnt},
        CurrCode         => $p{msg_cur},
        FormatCode       => 'xml',
        MsgHash          => Digest::MD5::md5_hex($p{msg}),
        Cmd              => 0,
        ExtIsError       => 0,
    };

    # Делаем запрос к базе.
    my $result = $self->{db}->add_message($params);

    # if ($self->{config}->{debug}) {
    #     $self->log('debug', 'add_message params: ' . remove_crlf(dumper($params)));
    #     $self->log('debug', 'add_message result: ' . remove_crlf(dumper($result)));
    # }

    # Если вернулась ошибка:
    if ($result->{Result} ne '0') {
        my $err_msg_db = $result->{ErrMsg};
        my ($err_code, $err_msg);
        if ($result->{Result} eq '1' || $result->{Result} eq '2') {
            $err_code = $result->{ErrCode};
            $err_msg = $result->{ErrMsg};
        }
        else {
            # это какая-то нестандартная ошибка
			# Залогировать ошибку
            $self->log('error', 'save_message_to_db: ' . $p{doc_id}
						. ': add_message error: ' . $result->{ErrCode} . ': ' . $result->{ErrMsg});
			# Сохранить ошибку
            $self->save_error(ERR_DATABASE);
            $err_code = ERR_PROCESSING;
            $err_msg = CyberFT::Errors::desc(ERR_PROCESSING);
            $self->{db_check_needed} = 1;
        }
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => $err_code, ErrMsg => $err_msg, ErrMsgDB => $err_msg_db};
    }

    my $real_receiver = $result->{RealReceiverSwift};
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', RealReceiver => $real_receiver};
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

# После возникновения необработанной ошибки во время обработки фрэйма, нужно вызвать recover.
# Эта функция разрывает соединение с брокером, что заставит его переподключиться при следующем обращении.
# Также проверяется соединение с базой. Если его нет, то оно восстанавливается.
sub recover {
    my $self = shift;
    if (defined $self->{broker}) {
        $self->{broker}->disconnect();
        $self->connect_broker();
    }
    unless (defined($self->{db}) && $self->{db}->ping()) {
		# Залогировать ошибку
        $self->log('error', 'Database connection lost');
        $self->connect_database();
    }
}

# Закрываем все соединения.
sub cleanup {
    my $self = shift;
    if (defined $self->{broker}) {
        $self->{broker}->disconnect;
    }
    if (defined $self->{db}) {
        $self->{db}->disconnect;
    }
}

sub log {
    my $self = shift;
    my $priority = shift;
    my $msg = shift;
    if (defined $self->{log_prefix}) {
        $msg = $self->{log_prefix}.$msg;
    }
    $self->{config}->{log_func}->($priority, $msg);
}

1;