package CyberFT::Database::OracleDatabase;
use base 'CyberFT::Database';

use strict;
use utf8;
use DBI;
use DBD::Oracle qw(:ora_types);
use Data::Dumper;

# Открываем соединение с базой.
sub connect {
    my ($self) = @_;
    my $config = $self->config;

    $ENV{'NLS_LANG'} = 'AMERICAN_AMERICA.UTF8';

    $self->{dbh} = DBI->connect(
        $config->{db_data_source},
        $config->{db_username},
        $config->{db_password},
        {
            RaiseError       => 0,
            PrintError       => 1,
            AutoCommit       => 1,
            LongReadLen      => 5242880,
            LongTruncOk      => 0,
            FetchHashKeyName => 'NAME_lc',
            ora_check_sql    => 0,
        }
    );

    unless (defined $self->{dbh}) {
        return {
            Result => -1,
            ErrCode => -1,
            ErrMsg => $DBI::errstr,
        };
    }

    my $res = $self->{dbh}->do("ALTER SESSION SET NLS_DATE_FORMAT='YYYY-MM-DD HH24:MI:SS'");
    unless ($res) {
        return {
            Result => -1,
            ErrCode => -1,
            ErrMsg => $self->{dbh}->errstr,
        };
    }
    $res = $self->{dbh}->do('ALTER SESSION SET CURRENT_SCHEMA = edo3');
    unless ($res) {
        return {
            Result => -1,
            ErrCode => -1,
            ErrMsg => $self->{dbh}->errstr,
        };
    }

    return {
        Result => 0,
        ErrCode => 0,
        ErrMsg => '',
    };
}

# Закрываем соединение с базой.
sub disconnect {
    my $self = shift;
    if ($self->{dbh}) {
        $self->{dbh}->disconnect;
    }
}

# Проверка соединения.
sub ping {
    my $self = shift;
    unless (defined $self->{dbh}) {
        return 0;
    }
    unless ($self->{dbh}->ping()) {
        return 0;
    }
    return 1;
}

# Дескриптор базы данных. Вернет undef, если соединение не установлено.
sub dbh {
    my $self = shift;
    return $self->{dbh};
}

# Подготовка запроса.
sub prepare {
    my ($self, $query, $opts) = @_;

    my $sth = $self->{dbh}->prepare($query, $opts);
    if (!$sth) {
        return (undef, $self->{dbh}->errstr);
    }

    return ($sth, undef);
}

# Подготовка запроса с кэшированием.
sub prepare_cached {
    my ($self, $query, $opts) = @_;

    my $sth = $self->{dbh}->prepare_cached($query, $opts);
    if (!$sth) {
        return (undef, $self->{dbh}->errstr);
    }

    return ($sth, undef);
}

# Добавление сообщения.
# Сохраняет сообщение в статусе «Ожидает отправки».
# В параметрах можно передать параметр MsgBody_FileName -  в этом случае сообщение будет считано из
# данного файла. Также, можно передать параметр MsgBody_FileHandle - в этом случае сообщение будет
# считано из данного файлового объекта. Если эти параметры не переданы, то сообщение берется из
# параметра MsgBody.
sub add_message {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    # Здесь будет указатель на временный блоб
    my $blob;

    # Создадим временный блоб
    my ($sth_create, $err) = $self->prepare(
        q{
            BEGIN
                DBMS_LOB.CREATETEMPORARY(:blob, TRUE);
            END;
        },
        { ora_auto_lob => 0 }
    );
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }
    $sth_create->bind_param_inout(':blob', \$blob, 64, {ora_type => ORA_BLOB});
    my $res = $sth_create->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth_create->errstr };
    }

    # Запишем туда данные
    if (defined $in->{MsgBody_FileName}) {
        open(my $fh, '<', $in->{MsgBody_FileName}) or return { Result => -1, ErrCode => -1, ErrMsg => "Cannot open file: $!" };
        binmode($fh);
        my $r = $self->_write_lob($blob, $fh);
        close($fh);
        if ($r->{Result} ne '0') {
            return $r;
        }
    }
    elsif (defined $in->{MsgBody_FileHandle}) {
        my $r = $self->_write_lob($blob, $in->{MsgBody_FileHandle});
        if ($r->{Result} ne '0') {
            return $r;
        }
    }
    else {
        open(my $fh, '<', \$in->{MsgBody});
        my $r  = $self->_write_lob($blob, $fh);
        close($fh);
        if ($r->{Result} ne '0') {
            return $r;
        }
    }

    # Сохраним сообщение передав ссылку на временный блоб
    my ($sth, $err) = $self->prepare(
        q{
            BEGIN
                :result := edo3.pk_message.addMessage_3(
                    :pcMsgCode,
                    :pcSenderSwift,
                    :pcReceiverSwift,
                    :pcSenderMsgCode,
                    :pcMsgHash,
                    :pbMsgBody,
                    :piCmd,
                    :piExtIsError,
                    :pcExtErrCode,
                    :pcExtErrMsg,
                    :piMessage,
                    :pcErrCode,
                    :pcErrMsg,
                    :piMessageLength,
                    :pnMessageSum,
                    :pnMessageCnt,
                    :pcCurrCode,
                    :pcFormatCode,
                    :pcRealReceiverSwift,
                    :pdatTimeLimit,
                    :piAnotherSegment,
                    :pcNextSwift,
                    :pdatDocTime
                );
            END;
        },
        { ora_auto_lob => 0 }
    );
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':pcMsgCode',       $in->{MsgCode}      );
    $sth->bind_param(':pcSenderSwift',   $in->{SenderSwift}  );
    $sth->bind_param(':pcReceiverSwift', $in->{ReceiverSwift});
    $sth->bind_param(':pcSenderMsgCode', $in->{SenderMsgCode});
    $sth->bind_param(':pcMsgHash',       $in->{MsgHash}      );
    $sth->bind_param(':pbMsgBody',       $blob,              {ora_type => ORA_BLOB});
    $sth->bind_param(':piCmd',           $in->{Cmd}          );
    $sth->bind_param(':piExtIsError',    $in->{ExtIsError}   );
    $sth->bind_param(':pcExtErrCode',    $in->{ExtErrCode}   );
    $sth->bind_param(':pcExtErrMsg',     $in->{ExtErrMsg}    );
    $sth->bind_param(':piMessageLength', $in->{MessageLength});
    $sth->bind_param(':pnMessageSum',    $in->{MessageSum}   );
    $sth->bind_param(':pnMessageCnt',    $in->{MessageCnt}   );
    $sth->bind_param(':pcCurrCode',      $in->{CurrCode}     );
    $sth->bind_param(':pcFormatCode',    $in->{FormatCode}   );
    $sth->bind_param(':pdatTimeLimit',   $in->{TimeLimit}    );
    $sth->bind_param(':pdatDocTime',     $in->{DocTime}      );

    # Output params
    $sth->bind_param_inout(':result',              \$out->{Result},              32);
    $sth->bind_param_inout(':piMessage',           \$out->{Message},             32);
    $sth->bind_param_inout(':pcErrCode',           \$out->{ErrCode},           4096);
    $sth->bind_param_inout(':pcErrMsg',            \$out->{ErrMsg},            4096);
    $sth->bind_param_inout(':pcRealReceiverSwift', \$out->{RealReceiverSwift}, 4096);
    $sth->bind_param_inout(':piAnotherSegment',    \$out->{AnotherSegment},      32);
    $sth->bind_param_inout(':pcNextSwift',         \$out->{NextSwift},         4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Установка статуса сообщения.
#    • 16 - Ошибка при доставке. Конечное состояние сообщения.
#    • 17 - Доставлен получателю. Конечное состояние сообщения.
#    • 18 - Доставлен получателю с ошибкой. Конечное состояние сообщения.
#    • 19 - Не доставлен. Конечное состояние сообщения.
#    • 31 - Ожидает отправки.
#    • 32 – Отправляется.
#    • 33 – Отправлено.
#    • 34 – Получено.
#    • 37 – Ошибка постановки в очередь.
#    • 38 – Ошибка отправки.
#    • 39 – Приостановлено.
sub set_message_status {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_message.setMessageStatus(
                :piMessage,
                :pcReceiverCode,
                :pcReceiverSwift,
                :piExtIsError,
                :pcExtErrCode,
                :pcExtErrMsg,
                :pcErrCode,
                :pcErrMsg,
                :pcSenderCode,
                :pcSenderSwift,
                :pcSenderMsgCode,
                :piSendStatus
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piMessage',       $in->{Message}      );
    $sth->bind_param(':pcReceiverCode',  $in->{ReceiverCode} );
    $sth->bind_param(':pcReceiverSwift', $in->{ReceiverSwift});
    $sth->bind_param(':piExtIsError',    $in->{ExtIsError}   );
    $sth->bind_param(':pcExtErrCode',    $in->{ExtErrCode}   );
    $sth->bind_param(':pcExtErrMsg',     $in->{ExtErrMsg}    );
    $sth->bind_param(':pcSenderCode',    $in->{SenderCode}   );
    $sth->bind_param(':pcSenderSwift',   $in->{SenderSwift}  );
    $sth->bind_param(':pcSenderMsgCode', $in->{SenderMsgCode});
    $sth->bind_param(':piSendStatus',    $in->{SendStatus}   );

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},    32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode}, 4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},  4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Получение следующего неотправленного сообщения.
# В параметрах можно передать MsgBody_FileName или MsgBody_FileHandle для записи тела сообщения в файл.
# Файл MsgBody_FileName будет создан только если успешно вернулось сообщение из базы.
# Если эти параметры не переданы, то сообщение вернется в MsgBody.
# Опциональный параметр SmartMsgBodyMaxSize определяет максимальный размер документа, который может
# быть считан в память, даже если указан MsgBody_FileName или MsgBody_FileHandle. Т.е. если документ
# не превышает указанный размер, он вернется в виде строки в параметре MsgBody, а MsgBody_FileName и
# MsgBody_FileHandle будут проигнорированы.
sub get_next_unsent {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(
        q{
            BEGIN
                :result := edo3.pk_message.getNextUnsent(
                    :pcErrCode,
                    :pcErrMsg,
                    :piMessage,
                    :pcReceiverSwift,
                    :pcMsgCode,
                    :pcSenderSwift,
                    :pcSenderMsgCode,
                    :pdatRegDate,
                    :pcMsgHash,
                    :pbMsgBody,
                    :piAnotherSegment,
                    :pcNextSwift,
                    :pcRcvLoginAddr,
                    :piRcvFrgReady,
                    :piRcvFrgSize,
                    :piRcvQueueLen,
                    :pdatTimeLimit,
                    :piTimeExired,
                    :piSendStatus
                );
            END;
        },
        {ora_auto_lob => 0}
    );
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    my $blob;

    # Output params
    $sth->bind_param_inout(':result',           \$out->{Result},           32);
    $sth->bind_param_inout(':pcErrCode',        \$out->{ErrCode},        4096);
    $sth->bind_param_inout(':pcErrMsg',         \$out->{ErrMsg},         4096);
    $sth->bind_param_inout(':piMessage',        \$out->{Message},          32);
    $sth->bind_param_inout(':pcReceiverSwift',  \$out->{ReceiverSwift},  4096);
    $sth->bind_param_inout(':pcMsgCode',        \$out->{MsgCode},        4096);
    $sth->bind_param_inout(':pcSenderSwift',    \$out->{SenderSwift},    4096);
    $sth->bind_param_inout(':pcSenderMsgCode',  \$out->{SenderMsgCode},  4096);
    $sth->bind_param_inout(':pdatRegDate',      \$out->{RegDate},          32);
    $sth->bind_param_inout(':pcMsgHash',        \$out->{MsgHash},        4096);
    $sth->bind_param_inout(':pbMsgBody',        \$blob,                    32, {ora_type => ORA_BLOB});
    $sth->bind_param_inout(':piAnotherSegment', \$out->{AnotherSegment},   32);
    $sth->bind_param_inout(':pcNextSwift',      \$out->{NextSwift},      4096);
    $sth->bind_param_inout(':pcRcvLoginAddr',   \$out->{RcvLoginAddr},   4096);
    $sth->bind_param_inout(':piRcvFrgReady',    \$out->{RcvFrgReady},      32);
    $sth->bind_param_inout(':piRcvFrgSize',     \$out->{RcvFrgSize},       32);
    $sth->bind_param_inout(':piRcvQueueLen',    \$out->{RcvQueueLen},      32);
    $sth->bind_param_inout(':pdatTimeLimit',    \$out->{TimeLimit},        32);
    $sth->bind_param_inout(':piTimeExired',     \$out->{TimeExired},       32);
    $sth->bind_param_inout(':piSendStatus',     \$out->{SendStatus},       32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    if ($out->{Result} eq '0' && $out->{Message} != 0) {
        my $read_lob_result;
        my $filename = $in->{MsgBody_FileName};
        my $filehandle = $in->{MsgBody_FileHandle};
        my $blob_size = undef;
        if (defined $in->{SmartMsgBodyMaxSize}) {
            # Если задан параметр SmartMsgBodyMaxSize, то документ может быть считан в память,
            # а не в файл, если его размер не превышает SmartMsgBodyMaxSize. Т.е. параметры
            # MsgBody_FileName и MsgBody_FileHandle будут проигнорированы, а документ
            # вернется в параметре MsgBody.
            my $blob_size = $self->{dbh}->ora_lob_length($blob);
            if ($blob_size <= $in->{SmartMsgBodyMaxSize}) {
                $filename = undef;
                $filehandle = undef;
            }
        }

        if (defined $filename) {
            open(my $fh, '>', $filename) or return { Result => -1, ErrCode => -1, ErrMsg => "Cannot open file: $!" };
            binmode($fh);
            $read_lob_result = $self->_read_lob($blob, $fh, $blob_size, $in->{Timeout});
            close($fh);
        }
        elsif (defined $filehandle) {
            $read_lob_result = $self->_read_lob($blob, $filehandle, $blob_size, $in->{Timeout});
        }
        else {
            open(my $fh, '>', \$out->{MsgBody});
            $read_lob_result  = $self->_read_lob($blob, $fh, $blob_size, $in->{Timeout});
            close($fh);
        }

        if ($read_lob_result->{Result} eq '0') {
            $out->{MsgBody_Length} = $read_lob_result->{Length};
        } else {
            if ($read_lob_result->{ErrCode} eq '-2') { # Timeout
                $out->{Result} = -1;
                $out->{ErrCode} = -2;
            } else {
                return $read_lob_result;
            }
        }
    }

    return $out;
}

# Получение сертификата участника.
sub get_member_cert_3 {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_message.getMemberCert_3(
                :pcFromTerminal,
                :pcTerminal,
                :pcKeyCode,
                :pcErrCode,
                :pcErrMsg,
                :piOperatorRole,
                :pbKeyBody,
                :piCertCenter,
                :piMemberType
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':pcFromTerminal', $in->{FromTerminal});
    $sth->bind_param(':pcTerminal',     $in->{Terminal}    );
    $sth->bind_param(':pcKeyCode',      $in->{KeyCode}     );
    $sth->bind_param(':piCertCenter',   $in->{CertCenter}  );

    # Output params
    $sth->bind_param_inout(':result',         \$out->{Result},          32);
    $sth->bind_param_inout(':pcErrCode',      \$out->{ErrCode},       4096);
    $sth->bind_param_inout(':pcErrMsg',       \$out->{ErrMsg},        4096);
    $sth->bind_param_inout(':piOperatorRole', \$out->{OperatorRole},    32);
    $sth->bind_param_inout(':pbKeyBody',      \$out->{KeyBody},      32768, {ora_type => ORA_BLOB});
    $sth->bind_param_inout(':piMemberType',   \$out->{MemberType},      32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Добавление сертификата (оператора) к сообщению.
sub add_message_cert {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_message.addMessageCert(
                :pcErrCode,
                :pcErrMsg,
                :pcFromTerminal,
                :piMessage,
                :pcTerminal,
                :pcKeyCode,
                :piIsError,
                :pcErrorInfo,
                :piRole,
                :piCertCenter
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':pcFromTerminal', $in->{FromTerminal});
    $sth->bind_param(':piMessage',      $in->{Message}     );
    $sth->bind_param(':pcTerminal',     $in->{Terminal}    );
    $sth->bind_param(':pcKeyCode',      $in->{KeyCode}     );
    $sth->bind_param(':piIsError',      $in->{IsError}     );
    $sth->bind_param(':pcErrorInfo',    $in->{ErrorInfo}   );
    $sth->bind_param(':piRole',         $in->{Role}        );
    $sth->bind_param(':piCertCenter',   $in->{CertCenter}  );

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},    32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode}, 4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},  4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Возвращает документ застрявший в состоянии "Отправлено" (33)
# Застрявшим считается документ, который висит в состоянии 33 более 10 минут
sub get_next_unconfirmed_sent {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(
        q{
            BEGIN
                :result := edo3.pk_message.getNextUnconfirmedSent(
                    :pcErrCode,
                    :pcErrMsg,
                    :piMessage,
                    :pcReceiverSwift,
                    :pcMsgCode,
                    :pcSenderSwift,
                    :pcSenderMsgCode,
                    :pdatRegDate,
                    :pcMsgHash,
                    :piAnotherSegment,
                    :pcNextSwift,
                    :pcRcvLoginAddr,
                    :piRcvFrgReady,
                    :piRcvFrgSize,
                    :piRcvQueueLen,
                    :pdatTimeLimit,
                    :piTimeExired,
                    :piSendStatus
                );
            END;
        },
        {ora_auto_lob => 0}
    );
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Output params
    $sth->bind_param_inout(':result',           \$out->{Result},           32);
    $sth->bind_param_inout(':pcErrCode',        \$out->{ErrCode},        4096);
    $sth->bind_param_inout(':pcErrMsg',         \$out->{ErrMsg},         4096);
    $sth->bind_param_inout(':piMessage',        \$out->{Message},          32);
    $sth->bind_param_inout(':pcReceiverSwift',  \$out->{ReceiverSwift},  4096);
    $sth->bind_param_inout(':pcMsgCode',        \$out->{MsgCode},        4096);
    $sth->bind_param_inout(':pcSenderSwift',    \$out->{SenderSwift},    4096);
    $sth->bind_param_inout(':pcSenderMsgCode',  \$out->{SenderMsgCode},  4096);
    $sth->bind_param_inout(':pdatRegDate',      \$out->{RegDate},          32);
    $sth->bind_param_inout(':pcMsgHash',        \$out->{MsgHash},        4096);
    $sth->bind_param_inout(':piAnotherSegment', \$out->{AnotherSegment},   32);
    $sth->bind_param_inout(':pcNextSwift',      \$out->{NextSwift},      4096);
    $sth->bind_param_inout(':pcRcvLoginAddr',   \$out->{RcvLoginAddr},   4096);
    $sth->bind_param_inout(':piRcvFrgReady',    \$out->{RcvFrgReady},      32);
    $sth->bind_param_inout(':piRcvFrgSize',     \$out->{RcvFrgSize},       32);
    $sth->bind_param_inout(':piRcvQueueLen',    \$out->{RcvQueueLen},      32);
    $sth->bind_param_inout(':pdatTimeLimit',    \$out->{TimeLimit},        32);
    $sth->bind_param_inout(':piTimeExired',     \$out->{TimeExired},       32);
    $sth->bind_param_inout(':piSendStatus',     \$out->{SendStatus},       32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Установка состояния для переотправки сообщения
sub set_message_status_resend {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(
        q{
            BEGIN
                :result := edo3.pk_message.setMessageStatusResend(
                    :piMessage,
                    :pcReceiverSwift,
                    :pcErrCode,
                    :pcErrMsg,
                    :pcSenderSwift,
                    :pcSenderMsgCode
                );
            END;
        },
        {ora_auto_lob => 0}
    );
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piMessage',       $in->{Message}      );
    $sth->bind_param(':pcReceiverSwift', $in->{ReceiverSwift});
    $sth->bind_param(':pcSenderSwift',   $in->{SenderSwift}  );
    $sth->bind_param(':pcSenderMsgCode', $in->{SenderMsgCode});

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},   32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode}, 4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},  4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Функция для инициализации типа ошибки
sub init_error_type {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            edo3.pk_err.initErrorType(
                :piErrType,
                :pcName
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piErrType', $in->{ErrType});
    $sth->bind_param(':pcName',    $in->{Name});

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return { Result => 0, ErrCode => 0, ErrMsg => 'Success' };
}

# Функция для инициализации справочника ошибки
sub init_error_info {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            edo3.pk_err.initErrorInfo(
                :piErrNum,
                :pcDescr,
                :pcDetailDescr,
                :pcMessage,
                :piParCnt,
                :pcPar1Descr,
                :pcPar2Descr,
                :pcPar3Descr,
                :pcRUMessage,
                :piErrType,
                :piLevel
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piErrNum',      $in->{ErrNum});
    $sth->bind_param(':pcDescr',       $in->{Descr});
    $sth->bind_param(':pcDetailDescr', $in->{DetailDescr});
    $sth->bind_param(':pcMessage',     $in->{Message});
    $sth->bind_param(':piParCnt',      $in->{ParCnt});
    $sth->bind_param(':pcPar1Descr',   $in->{Par1Descr});
    $sth->bind_param(':pcPar2Descr',   $in->{Par2Descr});
    $sth->bind_param(':pcPar3Descr',   $in->{Par3Descr});
    $sth->bind_param(':pcRUMessage',   $in->{RUMessage});
    $sth->bind_param(':piErrType',     $in->{ErrType});
    $sth->bind_param(':piLevel',       $in->{Level});

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return { Result => 0, ErrCode => 0, ErrMsg => 'Success' };
}

# Сохранение внешней ошибки в общем журнале ошибок
# save_external_error({Error => N, Par1 => S, Par2 => S, Par3 => S, CftBic => S, RecipientCode => S, DocType => S})
sub save_external_error {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare(q{
        BEGIN
            edo3.pk_err.saveExternalError(
                :piError,
                :pcPar1,
                :pcPar2,
                :pcPar3,
                :pcCftBic,
                :pcRecipientCode,
                :pcDocType
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piError',         $in->{Error});
    $sth->bind_param(':pcPar1',          $in->{Par1});
    $sth->bind_param(':pcPar2',          $in->{Par2});
    $sth->bind_param(':pcPar3',          $in->{Par3});
    $sth->bind_param(':pcCftBic',        $in->{CftBic});
    $sth->bind_param(':pcRecipientCode', $in->{RecipientCode});
    $sth->bind_param(':pcDocType',       $in->{DocType});

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return { Result => 0, ErrCode => 0, ErrMsg => 'Success' };
}

# Подготовка данных для ежедевного экспорта.
sub export_prepare_daily {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_export.prepareDaily(
                :pcErrCode,
                :pcErrMsg,
                :pdatPrepareDate,
                :pdatExportDate,
                :piForce
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':pdatExportDate', $in->{ExportDate});
    $sth->bind_param(':piForce',        $in->{Force});

    # Output params
    $sth->bind_param_inout(':result',          \$out->{Result},        32);
    $sth->bind_param_inout(':pcErrCode',       \$out->{ErrCode},     4096);
    $sth->bind_param_inout(':pcErrMsg',        \$out->{ErrMsg},      4096);
    $sth->bind_param_inout(':pdatPrepareDate', \$out->{PrepareDate},   32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Окончание формирования ежедевного экспорта.
sub export_finish_daily {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_export.finishDaily(
                :pcErrCode,
                :pcErrMsg,
                :pdatExportDate
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':pdatExportDate', $in->{ExportDate});

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},        32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode},     4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},      4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Подготовка данных для полного экспорта.
sub export_prepare_full {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_export.prepareFull(
                :pcErrCode,
                :pcErrMsg,
                :pdatPrepareDate,
                :pdatExportDate,
                :piForce
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piForce', $in->{Force});

    # Output params
    $sth->bind_param_inout(':result',          \$out->{Result},        32);
    $sth->bind_param_inout(':pcErrCode',       \$out->{ErrCode},     4096);
    $sth->bind_param_inout(':pcErrMsg',        \$out->{ErrMsg},      4096);
    $sth->bind_param_inout(':pdatPrepareDate', \$out->{PrepareDate},   32);
    $sth->bind_param_inout(':pdatExportDate',  \$out->{ExportDate},    32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Окончание формирования полного экспорта.
sub export_finish_full {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_export.finishFull(
                :pcErrCode,
                :pcErrMsg
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},        32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode},     4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},      4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Проверка - необходимо ли выполнять запрос на обновление данных.
sub import_check_request {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_import.checkRequest(
                :pcErrCode,
                :pcErrMsg,
                :piRequestType,
                :pdatRequestDate,
                :pcParentProc
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Output params
    $sth->bind_param_inout(':result',          \$out->{Result},          32);
    $sth->bind_param_inout(':pcErrCode',       \$out->{ErrCode},       4096);
    $sth->bind_param_inout(':pcErrMsg',        \$out->{ErrMsg},        4096);
    $sth->bind_param_inout(':piRequestType',   \$out->{RequestType},   4096);
    $sth->bind_param_inout(':pdatRequestDate', \$out->{RequestDate},     32);
    $sth->bind_param_inout(':pcParentProc',    \$out->{ParentProc},    4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Завершение работы с запросом на обновление данных.
sub import_finish_request {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_import.finishRequest(
                :pcErrCode,
                :pcErrMsg,
                :piRequestType
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piRequestType', $in->{RequestType});

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},     32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode},  4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},   4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Первоначальное действие по импорту журнала изменений.
sub import_start_member_import {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_import.startMemberImport(
                :pcErrCode,
                :pcErrMsg,
                :piImport,
                :piRequestType,
                :pcSource,
                :pcFileName,
                :pdatListDate,
                :pdatUnloadDate,
                :piCnt
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piRequestType',  $in->{RequestType});
    $sth->bind_param(':pcSource',       $in->{Source});
    $sth->bind_param(':pcFileName',     $in->{FileName});
    $sth->bind_param(':pdatListDate',   $in->{ListDate});
    $sth->bind_param(':pdatUnloadDate', $in->{UnloadDate});
    $sth->bind_param(':piCnt',          $in->{Cnt});

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},     32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode},  4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},   4096);
    $sth->bind_param_inout(':piImport',  \$out->{Import},     32);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Загрузка строки журнала импорта участников.
sub import_load_member_record {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_import.loadMemberRecord(
                :pcErrCode,
                :pcErrMsg,
                :piImport,
                :piExpId,
                :pcMemberCode,
                :pcSwiftCode,
                :pcMemberName,
                :pcRegistrInfo,
                :piStatus,
                :piBlock,
                :pcBlockInfo,
                :piLang,
                :piMemberType,
                :pcParentSwiftCode,
                :pcEngName,
                :piIsBank,
                :pcCntrCode2,
                :pcCityName,
                :pdatValiFrom,
                :pdatValiTo,
                :pcWebSite,
                :pcMemberPhone
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piImport',          $in->{Import});
    $sth->bind_param(':piExpId',           $in->{ExpId});
    $sth->bind_param(':pcMemberCode',      $in->{MemberCode});
    $sth->bind_param(':pcSwiftCode',       $in->{SwiftCode});
    $sth->bind_param(':pcMemberName',      $in->{MemberName});
    $sth->bind_param(':pcRegistrInfo',     $in->{RegistrInfo});
    $sth->bind_param(':piStatus',          $in->{Status});
    $sth->bind_param(':piBlock',           $in->{Block});
    $sth->bind_param(':pcBlockInfo',       $in->{BlockInfo});
    $sth->bind_param(':piLang',            $in->{Lang});
    $sth->bind_param(':piMemberType',      $in->{MemberType});
    $sth->bind_param(':pcParentSwiftCode', $in->{ParentSwiftCode});
    $sth->bind_param(':pcEngName',         $in->{EngName});
    $sth->bind_param(':piIsBank',          $in->{IsBank});
    $sth->bind_param(':pcCntrCode2',       $in->{CntrCode2});
    $sth->bind_param(':pcCityName',        $in->{CityName});
    $sth->bind_param(':pdatValiFrom',      $in->{ValiFrom});
    $sth->bind_param(':pdatValiTo',        $in->{ValiTo});
    $sth->bind_param(':pcWebSite',         $in->{WebSite});
    $sth->bind_param(':pcMemberPhone',     $in->{MemberPhone});

    # Output params
    $sth->bind_param_inout(':result',    \$out->{Result},     32);
    $sth->bind_param_inout(':pcErrCode', \$out->{ErrCode},  4096);
    $sth->bind_param_inout(':pcErrMsg',  \$out->{ErrMsg},   4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

# Обработка журнала импорта.
sub import_process_import {
    my $self = shift;
    my $in = shift;
    my $out = {};

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

     my ($sth, $err) = $self->prepare(q{
        BEGIN
            :result := edo3.pk_import.processImport(
                :pcErrCode,
                :pcErrMsg,
                :piImport,
                :pcMail,
                :piRequestType,
                :pcFileName,
                :pdatListDate,
                :piStatus,
                :pdatProcessedDate,
                :piListCnt,
                :piProcessedCnt,
                :piAddCnt,
                :piEditCnt,
                :piDelCnt,
                :piErrCnt,
                :piWarnCnt,
                :pcErrInfo
            );
        END;
    });
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    # Input params
    $sth->bind_param(':piImport', $in->{Import});

    # Output params
    $sth->bind_param_inout(':result',            \$out->{Result},          32);
    $sth->bind_param_inout(':pcErrCode',         \$out->{ErrCode},       4096);
    $sth->bind_param_inout(':pcErrMsg',          \$out->{ErrMsg},        4096);
    $sth->bind_param_inout(':pcMail',            \$out->{Mail},          4096);
    $sth->bind_param_inout(':piRequestType',     \$out->{RequestType},     32);
    $sth->bind_param_inout(':pcFileName',        \$out->{FileName},      4096);
    $sth->bind_param_inout(':pdatListDate',      \$out->{ListDate},        32);
    $sth->bind_param_inout(':piStatus',          \$out->{Status},          32);
    $sth->bind_param_inout(':pdatProcessedDate', \$out->{ProcessedDate},   32);
    $sth->bind_param_inout(':piListCnt',         \$out->{ListCnt},         32);
    $sth->bind_param_inout(':piProcessedCnt',    \$out->{ProcessedCnt},    32);
    $sth->bind_param_inout(':piAddCnt',          \$out->{AddCnt},          32);
    $sth->bind_param_inout(':piEditCnt',         \$out->{EditCnt},         32);
    $sth->bind_param_inout(':piDelCnt',          \$out->{DelCnt},          32);
    $sth->bind_param_inout(':piErrCnt',          \$out->{ErrCnt},          32);
    $sth->bind_param_inout(':piWarnCnt',         \$out->{WarnCnt},         32);
    $sth->bind_param_inout(':pcErrInfo',         \$out->{ErrInfo},       4096);

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    return $out;
}

sub get_sys_params {
    my $self = shift;
    return undef unless ($self->{dbh});
    my $data = $self->{dbh}->selectall_arrayref('select par_code, par_value from edo3.w_sys_params', {Slice => {}});
    return undef unless ($data);
    my $params = {};
    for my $row (@$data) {
        $params->{$row->{par_code}} = $row->{par_value};
    }
    return $params;
}

sub get_receiver_code {
    my $self = shift;
    my $sender_message_code = shift;
    my $sender_code = shift;

    my $message_info = $self->get_message_info($sender_message_code, $sender_code);
    return undef unless $message_info;
    return $message_info->{receiver};
}

sub get_message_info {
    my $self = shift;
    my $sender_message_code = shift;
    my $sender_code = shift;

    return undef unless ($self->{dbh});

    my $message_info;
    eval {
        my $results = $self->{dbh}->selectrow_arrayref(
            q{
                select
                    message_id,
                    snd_member_swift_code,
                    rcv_member_swift_code,
                    message_code
                from edo3.w_messages
                where
                    sender_msg_code = ?
                    and snd_full_swift_code = ?
            },
            {},
            $sender_message_code,
            $sender_code
        );
        return unless defined($results) && @$results > 0;
        $message_info = {
            message_id => $results->[0],
            sender     => $results->[1],
            receiver   => $results->[2],
            doc_type   => $results->[3]
        };
    };
    return $message_info;
}

sub save_currency_rate {
    my ($self, $params) = @_;
    die 'Not supported';
}

sub _read_lob {
    my ($self, $lob, $fh, $lob_size, $timeout) = @_;

    my $offset = 1;
    my $chunk_size = 512*1024;

    my $result;
    eval {
        local $SIG{ALRM} = sub { die 'TIMEOUT' };
        $result = eval {
            alarm $timeout || 0;
            my $len = $lob_size;
            unless (defined $len) {
                $len = $self->{dbh}->ora_lob_length($lob);
            }
            if (defined $self->{dbh}->err) {
                return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot get lob length: ' . $self->{dbh}->errstr };
            }
            if ($len == 0) {
                return { Result => 0, ErrCode => 0, ErrMsg => '', Length => 0 };
            }

            while (1) {
                my $data = $self->{dbh}->ora_lob_read($lob, $offset, $chunk_size);
                if (length($data) == 0) {
                    last;
                }
                if (defined $self->{dbh}->err) {
                    return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot read lob: ' . $self->{dbh}->errstr };
                }
                print $fh $data;
                $offset += $chunk_size;
            }

            return { Result => 0, ErrCode => 0, ErrMsg => '', Length => $len };
        };
        alarm 0;
        die $@ if $@;
    };
    my $exception = $@;
    if ($exception =~ /^TIMEOUT/) {
        $result = { Result => -1, ErrCode => -2, ErrMsg => 'Reading LOB timed out' };
    } elsif ($exception) {
        warn $exception;
    }
    return $result;
}

sub _write_lob {
    my ($self, $lob, $fh) = @_;

    my $offset = 1;
    my $chunk_size = 512*1024;

    while (read($fh, my $data, $chunk_size)) {
        $self->{dbh}->ora_lob_write($lob, $offset, $data);
        if (defined $self->{dbh}->err) {
            return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot write lob: ' . $self->{dbh}->errstr };
        }
        $offset += length($data);
    }

    return { Result => 0, ErrCode => 0, ErrMsg => ''};
}

1;