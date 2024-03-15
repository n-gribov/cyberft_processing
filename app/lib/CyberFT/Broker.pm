# Класс для работы со STOMP-брокером

package CyberFT::Broker;

use strict;
use utf8;
use Data::Dumper;
use Data::UUID ();
use Net::Stomp;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
}

# Метод открывает сосединение с брокером сообщений
sub connect {
    my $self = shift;
	# Параметры хоста, порта, логина, пароля, логирующей функции и попыток реконнекта
    my ($host, $port, $user, $pass, $log_func, $reconnects) = @_;
	# 0 - пытается подключиться бесконечно
    $reconnects = (defined $reconnects) ? $reconnects : 0;

    eval {
		# Количество попыток
        my $attempt = 1;
		# Бесконечный цикл
        while (1) {
            my $f = eval {
				# Создать объект STOMP с переданными параметрами
                $self->{stomp} = Net::Stomp->new({
                    hostname                   => $host,
                    port                       => $port,
                    initial_reconnect_attempts => 1,
                    reconnect_attempts         => $reconnects,
                    logger                     => CyberFT::Broker::Logger->new($log_func),
                });
				# Вернуть результат установки соединения
                return $self->{stomp}->connect({
                    login    => $user,
                    passcode => $pass,
                });
            };
            my $exception = $@;
			# Если не было исключения
            unless ($exception) {
				# Если пришёл ответ CONNECTED
                if ($f->command eq 'CONNECTED') {
					# Выйти из цикла
                    last;
                }
            }
			# Если указано количество попыток реконнекта и онри исчерпаны
            if ($reconnects > 0 && $attempt >= $reconnects) {
				# Залогировать предупреждение
                $log_func->('warning', 'Broker: reconnect attempts count exceeded');
				# Если было исключение
                if ($exception) {
					# Завершиться с исключением
                    die $exception;
                }
				# Если пришёл ответ ERROR
                if ($f->command eq 'ERROR') {
					# Завершиться с сообщением
                    die $f->body;
                }
				# Завершиться с неизвестной ошибкой
                die "unknown error";
            }
			# Увеличить номер попытки
            $attempt += 1;
			# Пауза
            sleep(1);
			# Залогировать сервисное сообщение
            $log_func->('info', "Broker: trying to reconnect, attempt: $attempt");
        }
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Message broker connection error: ' . $err};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод подписывается на очередь
sub subscribe {
    my $self = shift;
	# Параметр названия очереди
    my $queue = shift;

    eval {
		# Вызвать команду STOMP subscribe
        $self->{stomp}->subscribe({
            destination => $queue,
            ack         => 'client'
        });
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Message broker subscribe error: ' . $err};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод закрывает соединение с брокером
# Коннектится заново автоматически, если вызвать другие комманды
sub disconnect {
    my $self = shift;
    eval {
		# Закрыть соединение
        $self->{stomp}->disconnect;
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Message broker disconnect error: ' . $err};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод читает следующее сообщение
sub recv_frame {
    my $self = shift;	
	# Параметр таймаута
    my $timeout = shift;

    my $frame;
    eval {
		# Получить фрейм
    	$frame = $self->{stomp}->receive_frame({ timeout => $timeout });
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Закрыть соединение
        $self->disconnect;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Frame read error: ' . $err};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', Frame => $frame};
}

# Метод отправляет подтверждение (переход к следующему сообщению)
sub send_ack {
    my $self = shift;
	# Параметр фрейма
    my $frame = shift;

    eval {
		# Отправить ACK
        $self->{stomp}->ack({frame => $frame});
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Закрыть соединение
        $self->disconnect;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Frame ack send error: ' . $err};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод отправляет сообщение в очередь
sub send_frame {
    my $self = shift;
	# Параметр имени очереди
    my $queue = shift;
	# Параметр сообщения
    my $msg = shift;
	# Параметр заголовков
    my $headers = shift;
	# Параметр таймаута
    my $timeout = shift;
	# По умолчанию таймаут 10
    $timeout = (defined $timeout) ? $timeout : 10;

    # Отправка сообщения
    my $receipt_id;
    eval {
		# Создать UUID для подтверждения
        $receipt_id = Data::UUID->new->create_str();
		# Создать список параметров
        my $params = {destination => $queue, receipt => $receipt_id, body => $msg};
		# Если заголовки представлены хеш-таблицей
        if (defined $headers && ref $headers eq 'HASH') {
			# Перебрать ключи хеш-таблицы
            for my $key (keys %$headers) {
				# Добавить ключи и значения в список параметров
                $params->{$key} = $headers->{$key};
            }
        }
		# Послать параметры
        $self->{stomp}->send($params);
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Закрыть соединение
        $self->disconnect;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Frame send error: ' . $err};
    }

    # Получение подтверждения
    my $f;
    eval {
		# Получить фрейм
        $f = $self->{stomp}->receive_frame({timeout => $timeout});
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Закрыть соединение
        $self->disconnect;
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Frame receipt receive error: ' . $err};
    }

    # Проверить, получен ли корректный ответ, что сообщение успешно встало в очередь
    if (
        defined $f
        && $f->command eq 'RECEIPT'
        && $f->headers->{'receipt-id'} eq $receipt_id
    ) {
		# Вернуть успешный результат
        return {Result => 0, ErrCode => 0, ErrMsg => ''};
    }

    # Если брокер вернул ошибку, то передать её выше
    if (defined $f && $f->command eq 'ERROR') {
        my $err = $f->body;
		# Очистить спецсимволы в тексте
        $err =~ s/^\s*|\s*$//g;
        $err =~ s/[\r\n]/ /g;
		# Вернуть результат с ошибкой
        return {
            Result => 1, ErrCode => 10,
            ErrMsg => 'ERROR response from broker ('.$err.')'
        };
    }

    # Не вернулись ни корректный RECEIPT ни ERROR. Вернем ошибку и переподключимся
	# Закрыть соединение
    $self->disconnect;
	# Вернуть результат с ошибкой
    return {Result => 1, ErrCode => 10, ErrMsg => 'No RECEIPT response from broker'};
}

# Пакет CyberFT::Broker::Logger нужен, чтобы выводить сообщения от брокера в общий лог.
{
    package CyberFT::Broker::Logger;
    use strict;

    sub new {
        my $class = shift;
        my $log_func = shift;
        my $self = {log_func => $log_func};
        bless $self, $class;
    }

	# Описание методов
    sub debug { my $self=shift; my $msg = join('', @_); $self->{log_func}->('debug',   'Broker: '.$msg);}
    sub info  { my $self=shift; my $msg = join('', @_); $self->{log_func}->('info',    'Broker: '.$msg);}
    sub warn  { my $self=shift; my $msg = join('', @_); $self->{log_func}->('warning', 'Broker: '.$msg);}
    sub error { my $self=shift; my $msg = join('', @_); $self->{log_func}->('error',   'Broker: '.$msg);}
    sub fatal { my $self=shift; my $msg = join('', @_); $self->{log_func}->('error',   'Broker: '.$msg);}
}

1;