package CyberFT::Database::PostgresDatabase;
use base 'CyberFT::Database';

use strict;
use utf8;
use DBI;
use Data::Dumper;

# Открываем соединение с базой.
sub connect {
    my ($self) = @_;
    my $config = $self->config;

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
        }
    );

    unless (defined $self->{dbh}) {
        return {
            Result => -1,
            ErrCode => -1,
            ErrMsg => $DBI::errstr,
        };
    }

    my $res = $self->{dbh}->do('set datestyle to "ISO, YMD"');
    unless ($res) {
        return {
            Result => -1,
            ErrCode => -1,
            ErrMsg => $self->{dbh}->errstr,
        };
    }
    $res = $self->{dbh}->do('set search_path to cyberft');
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
    my ($self, $params) = @_;

    # Проверим, есть ли соединение с базой.
    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my $create_lob_result;
    if (defined $params->{MsgBody_FileName}) {
        open(my $fh, '<', $params->{MsgBody_FileName}) or return { Result => -1, ErrCode => -1, ErrMsg => "Cannot open file: $!" };
        binmode($fh);
        $create_lob_result = $self->create_lob($fh);
        close($fh);
    }
    elsif (defined $params->{MsgBody_FileHandle}) {
        $create_lob_result = $self->create_lob($params->{MsgBody_FileHandle});
    }
    else {
        open(my $fh, '<', \$params->{MsgBody});
        $create_lob_result  = $self->create_lob($fh);
        close($fh);

    }
    if ($create_lob_result->{Result} ne '0') {
        return $create_lob_result;
    }
    my $lob_oid = $create_lob_result->{LobOid};

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout           as has_error,
                pcerrcodeout           as error_code,
                pcerrmsgout            as error_message,
                pimessageout           as message_id,
                pcrealreceiverswiftout as real_receiver_swift,
                pianothersegmentout    as another_segment,
                pcnextswiftout         as next_swift
            from cyberft.p_message_add_message(
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
                :piMessageLength,
                :pnMessageSum,
                :pnMessageCnt,
                :pcCurrCode,
                :pcFormatCode,
                :pdatTimeLimit,
                :pdatDocTime
            )
        },
        {
            pcMsgCode       => $params->{MsgCode},
            pcSenderSwift   => $params->{SenderSwift},
            pcReceiverSwift => $params->{ReceiverSwift},
            pcSenderMsgCode => $params->{SenderMsgCode},
            pcMsgHash       => $params->{MsgHash},
            pbMsgBody       => $lob_oid,
            piCmd           => $params->{Cmd},
            piExtIsError    => $params->{ExtIsError},
            pcExtErrCode    => $params->{ExtErrCode},
            pcExtErrMsg     => $params->{ExtErrMsg},
            piMessageLength => $params->{MessageLength},
            pnMessageSum    => $params->{MessageSum},
            pnMessageCnt    => $params->{MessageCnt},
            pcCurrCode      => $params->{CurrCode},
            pcFormatCode    => $params->{FormatCode},
            pdatTimeLimit   => $params->{TimeLimit},
            pdatDocTime     => $params->{DocTime},
        },
        {
            message_id          => 'Message',
            real_receiver_swift => 'RealReceiverSwift',
            another_segment     => 'AnotherSegment',
            next_swift          => 'NextSwift',
        }
    );

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
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_message_set_message_status(
                :piMessage,
                :pcReceiverCode,
                :pcReceiverSwift,
                :piExtIsError,
                :pcExtErrCode,
                :pcExtErrMsg,
                :pcSenderCode,
                :pcSenderSwift,
                :pcSenderMsgCode,
                :piSendStatus
            )
        },
        {
            piMessage       => $params->{Message},
            pcReceiverCode  => $params->{ReceiverCode},
            pcReceiverSwift => $params->{ReceiverSwift},
            piExtIsError    => $params->{ExtIsError},
            pcExtErrCode    => $params->{ExtErrCode},
            pcExtErrMsg     => $params->{ExtErrMsg},
            pcSenderCode    => $params->{SenderCode},
            pcSenderSwift   => $params->{SenderSwift},
            pcSenderMsgCode => $params->{SenderMsgCode},
            piSendStatus    => $params->{SendStatus},
        }
    );
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
    my ($self, $params) = @_;

    my $result = $self->execute_db_api_function(
        q{
            select
                piiserrorout                                       as has_error,
                pcerrcodeout                                       as error_code,
                pcerrmsgout                                        as error_message,
                pimessageout                                       as message,
                pcreceiverswiftout                                 as receiver_swift,
                pcmsgcodeout                                       as msg_code,
                pcsenderswiftout                                   as sender_swift,
                pcsendermsgcodeout                                 as sender_msg_code,
                to_char(pdatregdateout, 'yyyy-mm-dd hh24:mi:ss')   as reg_date,
                pcmsghashout                                       as msg_hash,
                pbmsgbodyout                                       as msg_body,
                pianothersegmentout                                as another_segment,
                pcnextswiftout                                     as next_swift,
                pcrcvloginaddrout                                  as rcv_login_addr,
                pircvfrgreadyout                                   as rcv_frg_ready,
                pircvfrgsizeout                                    as rcv_frg_size,
                pircvqueuelenout                                   as rcv_queue_len,
                to_char(pdattimelimitout, 'yyyy-mm-dd hh24:mi:ss') as time_limit,
                pitimeexiredout                                    as time_expired,
                pisendstatusout                                    as send_status
            from cyberft.p_message_get_next_unsent()
        },
        undef,
        {
            message         => 'Message',
            receiver_swift  => 'ReceiverSwift',
            msg_code        => 'MsgCode',
            sender_swift    => 'SenderSwift',
            sender_msg_code => 'SenderMsgCode',
            reg_date        => 'RegDate',
            msg_hash        => 'MsgHash',
            msg_body        => 'MsgBody_LobOid',
            another_segment => 'AnotherSegment',
            next_swift      => 'NextSwift',
            rcv_login_addr  => 'RcvLoginAddr',
            rcv_frg_ready   => 'RcvFrgReady',
            rcv_frg_size    => 'RcvFrgSize',
            rcv_queue_len   => 'RcvQueueLen',
            time_limit      => 'TimeLimit',
            time_expired    => 'TimeExired',
            send_status     => 'SendStatus',
        }
    );

    if ($result->{Result} eq '0' && $result->{Message} != 0) {
        my $read_lob_result;
        my $filename = $params->{MsgBody_FileName};
        my $filehandle = $params->{MsgBody_FileHandle};
        my $msg_body_size = undef;
        if (defined $params->{SmartMsgBodyMaxSize}) {
            # Если задан параметр SmartMsgBodyMaxSize, то документ может быть считан в память,
            # а не в файл, если его размер не превышает SmartMsgBodyMaxSize. Т.е. параметры
            # MsgBody_FileName и MsgBody_FileHandle будут проигнорированы, а документ
            # вернется в параметре MsgBody.
            $msg_body_size = $self->get_lob_size($result->{MsgBody_LobOid});
            if ($msg_body_size <= $params->{SmartMsgBodyMaxSize}) {
                $filename = undef;
                $filehandle = undef;
            }
        }

        if (defined $filename) {
            open(my $fh, '>', $filename) or return { Result => -1, ErrCode => -1, ErrMsg => "Cannot open file: $!" };
            binmode($fh);
            $read_lob_result = $self->read_lob($result->{MsgBody_LobOid}, $fh, $params->{Timeout});
            close($fh);
        }
        elsif (defined $filehandle) {
            $read_lob_result = $self->read_lob($result->{MsgBody_LobOid}, $filehandle, $params->{Timeout});
        }
        else {
            open(my $fh, '>', \$result->{MsgBody});
            $read_lob_result  = $self->read_lob($result->{MsgBody_LobOid}, $fh, $params->{Timeout});
            close($fh);
        }

        if ($read_lob_result->{Result} eq '0') {
            $result->{MsgBody_Length} = $read_lob_result->{Length};
        } else {
            if ($read_lob_result->{ErrCode} eq '-2') { # Timeout
                $result->{Result} = -1;
                $result->{ErrCode} = -2;
            } else {
                return $read_lob_result;
            }
        }
    }

    return $result;
}

# Получение сертификата участника.
sub get_member_cert_3 {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pioperatorroleout as operator_role,
                pbkeybodyout as key_body,
                pimembertypeout as member_type
            from cyberft.p_message_get_member_cert_3(
                :pcFromTerminal,
                :pcTerminal,
                :pcKeyCode,
                :piCertCenter
            )
        },
        {
            pcFromTerminal => $params->{FromTerminal},
            pcTerminal     => $params->{Terminal},
            pcKeyCode      => $params->{KeyCode},
            piCertCenter   => $params->{CertCenter},
        },
        {
            operator_role => 'OperatorRole',
            key_body      => 'KeyBody',
            member_type   => 'MemberType',
        }
    );
}

# Добавление сертификата (оператора) к сообщению.
sub add_message_cert {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_message_add_message_cert(
                :pcFromTerminal,
                :piMessage,
                :pcTerminal,
                :pcKeyCode,
                :piIsError,
                :pcErrorInfo,
                :piRole,
                :piCertCenter
            )
        },
        {
            pcFromTerminal => $params->{FromTerminal},
            piMessage      => $params->{Message},
            pcTerminal     => $params->{Terminal},
            pcKeyCode      => $params->{KeyCode},
            piIsError      => $params->{IsError},
            pcErrorInfo    => $params->{ErrorInfo},
            piRole         => $params->{Role},
            piCertCenter   => $params->{CertCenter},
        }
    );
}

# Возвращает документ застравший в состоянии "Отправлено" (33)
# Застрявшим считается документ, который висит в состоянии 33 более 10 минут
sub get_next_unconfirmed_sent {
    my ($self) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout        as has_error,
                pcerrcodeout        as error_code,
                pcerrmsgout         as error_message,
                pimessageout        as message,
                pcreceiverswiftout  as receiver_swift,
                pcmsgcodeout        as msg_code,
                pcsenderswiftout    as sender_swift,
                pcsendermsgcodeout  as sender_msg_code,
                pdatregdateout      as reg_date,
                pcmsghashout        as msg_hash,
                pianothersegmentout as another_segment,
                pcnextswiftout      as next_swift,
                pcrcvloginaddrout   as rcv_login_addr,
                pircvfrgreadyout    as rcv_frg_ready,
                pircvfrgsizeout     as rcv_frg_size,
                pircvqueuelenout    as rcv_queue_len,
                pdattimelimitout    as time_limit,
                pitimeexiredout     as time_expired,
                pisendstatusout     as send_status
            from cyberft.p_message_get_next_unconfirmed_sent()
        },
        undef,
        {
            message         => 'Message',
            receiver_swift  => 'ReceiverSwift',
            msg_code        => 'MsgCode',
            sender_swift    => 'SenderSwift',
            sender_msg_code => 'SenderMsgCode',
            reg_date        => 'RegDate',
            msg_hash        => 'MsgHash',
            another_segment => 'AnotherSegment',
            next_swift      => 'NextSwift',
            rcv_login_addr  => 'RcvLoginAddr',
            rcv_frg_ready   => 'RcvFrgReady',
            rcv_frg_size    => 'RcvFrgSize',
            rcv_queue_len   => 'RcvQueueLen',
            time_limit      => 'TimeLimit',
            time_expired    => 'TimeExired',
            send_status     => 'SendStatus',
        }
    );
}

# Установка состояния для переотправки сообщения
sub set_message_status_resend {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_message_set_message_resend(
                :piMessage,
                :pcReceiverSwift,
                :pcSenderSwift,
                :pcSenderMsgCode
            )
        },
        {
            piMessage       => $params->{Message},
            pcReceiverSwift => $params->{ReceiverSwift},
            pcSenderSwift   => $params->{SenderSwift},
            pcSenderMsgCode => $params->{SenderMsgCode},
        }
    );
}

# Функция для инициализации типа ошибки
sub init_error_type {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_error_api_init_type(:piErrType, :pcName)
        },
        {
            piErrType => $params->{ErrType},
            pcName    => $params->{Name},
        }
    );
}

# Функция для инициализации справочника ошибки
sub init_error_info {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_error_api_init_error(
                :piErrNum,
                :pcCode,
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
            )
        },
        {
            piErrNum      => $params->{ErrNum},
            pcCode        => $params->{Code},
            pcDescr       => $params->{Descr},
            pcDetailDescr => $params->{DetailDescr},
            pcMessage     => $params->{Message},
            piParCnt      => $params->{ParCnt},
            pcPar1Descr   => $params->{Par1Descr},
            pcPar2Descr   => $params->{Par2Descr},
            pcPar3Descr   => $params->{Par3Descr},
            pcRUMessage   => $params->{RUMessage},
            piErrType     => $params->{ErrType},
            piLevel       => $params->{Level},
        }
    );
}

# Сохранение внешней ошибки в общем журнале ошибок
# save_external_error({Error => N, Par1 => S, Par2 => S, Par3 => S, CftBic => S, RecipientCode => S, DocType => S})
sub save_external_error {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_error_api_save_external(
                :piError,
                :pcPar1,
                :pcPar2,
                :pcPar3,
                :pcCftBic,
                :pcRecipientCode,
                :pcDocType,
                :pcExtPar1,
                :pcExtPar2,
                :pcExtPar3,
                :pcExtPar4,
                :pcExtPar5,
                :pcExtPar6,
                :pcExtPar7,
                :pcExtPar8,
                :pcExtPar9
            )
        },
        {
            piError         => $params->{Error},
            pcPar1          => $params->{Par1},
            pcPar2          => $params->{Par2},
            pcPar3          => $params->{Par3},
            pcCftBic        => $params->{CftBic},
            pcRecipientCode => $params->{RecipientCode},
            pcDocType       => $params->{DocType},
            pcExtPar1       => $params->{ExtPar1},
            pcExtPar2       => $params->{ExtPar2},
            pcExtPar3       => $params->{ExtPar3},
            pcExtPar4       => $params->{ExtPar4},
            pcExtPar5       => $params->{ExtPar5},
            pcExtPar6       => $params->{ExtPar6},
            pcExtPar7       => $params->{ExtPar7},
            pcExtPar8       => $params->{ExtPar8},
            pcExtPar9       => $params->{ExtPar9},
        }
    );
}

# Подготовка данных для ежедевного экспорта.
sub export_prepare_daily {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                to_char(pdatpreparedateout, 'yyyy-mm-dd hh24:mi:ss') as prepare_date
            from cyberft.p_export_prepare_daily(
                :pdatExportDate,
                :piForce
            )
        },
        {
            pdatExportDate => $params->{ExportDate},
            piForce        => $params->{Force},
        },
        {
            prepare_date => 'PrepareDate',
        }
    );
}

# Окончание формирования ежедевного экспорта.
sub export_finish_daily {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_export_finish_daily(:pdatExportDate)
        },
        {
            pdatExportDate => $params->{ExportDate},
        }
    );
}

# Подготовка данных для полного экспорта.
sub export_prepare_full {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                to_char(pdatpreparedateout, 'yyyy-mm-dd hh24:mi:ss') as prepare_date,
                to_char(pdatexportdateout, 'yyyy-mm-dd hh24:mi:ss') as export_date
            from cyberft.p_export_prepare_full(:piForce)
        },
        {
            piForce => $params->{Force},
        },
        {
            prepare_date => 'PrepareDate',
            export_date => 'ExportDate',
        }
    );
}

# Окончание формирования полного экспорта.
sub export_finish_full {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_export_finish_full()
        }
    );
}

# Проверка - необходимо ли выполнять запрос на обновление данных.
sub import_check_request {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pirequesttypeout as request_type,
                to_char(pdatrequestdateout, 'yyyy-mm-dd hh24:mi:ss') as request_date,
                pcparentprocout as parent_proc
            from cyberft.p_import_check_request()
        },
        undef,
        {
            request_type => 'RequestType',
            request_date => 'RequestDate',
            parent_proc  => 'ParentProc',
        }
    );
}

# Завершение работы с запросом на обновление данных.
sub import_finish_request {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_import_finish_request(:piRequestType)
        },
        {
            piRequestType => $params->{RequestType},
        }
    );
}

# Первоначальное действие по импорту журнала изменений.
sub import_start_member_import {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                piimportout as import
            from cyberft.p_import_start_member_import(
                :piRequestType,
                :pcSource,
                :pcFileName,
                :pdatListDate,
                :pdatUnloadDate,
                :piCnt
            )
        },
        {
            piRequestType  => $params->{RequestType},
            pcSource       => $params->{Source},
            pcFileName     => $params->{FileName},
            pdatListDate   => $params->{ListDate},
            pdatUnloadDate => $params->{UnloadDate},
            piCnt          => $params->{Cnt},
        },
        {
            import => 'Import',
        }
    );
}

# Загрузка строки журнала импорта участников.
sub import_load_member_record {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_import_load_mamber_record(
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
                to_date(:pdatValiFrom, 'dd.mm.yyyy'),
                to_date(:pdatValiTo, 'dd.mm.yyyy'),
                :pcWebSite,
                :pcMemberPhone
            )
        },
        {
            piImport          => $params->{Import},
            piExpId           => $params->{ExpId},
            pcMemberCode      => $params->{MemberCode},
            pcSwiftCode       => $params->{SwiftCode},
            pcMemberName      => $params->{MemberName},
            pcRegistrInfo     => $params->{RegistrInfo},
            piStatus          => $params->{Status},
            piBlock           => $params->{Block},
            pcBlockInfo       => $params->{BlockInfo},
            piLang            => $params->{Lang},
            piMemberType      => $params->{MemberType},
            pcParentSwiftCode => $params->{ParentSwiftCode},
            pcEngName         => $params->{EngName},
            piIsBank          => $params->{IsBank},
            pcCntrCode2       => $params->{CntrCode2},
            pcCityName        => $params->{CityName},
            pdatValiFrom      => $params->{ValiFrom},
            pdatValiTo        => $params->{ValiTo},
            pcWebSite         => $params->{WebSite},
            pcMemberPhone     => $params->{MemberPhone},
        }
    );
}

# Обработка журнала импорта.
sub import_process_import {
    my ($self, $params) = @_;

    return $self->execute_db_api_function(
        q{
            select
                piiserrorout                                           as has_error,
                pcerrcodeout                                           as error_code,
                pcerrmsgout                                            as error_message,
                pcmailout                                              as mail,
                pirequesttypeout                                       as request_type,
                pcfilenameout                                          as file_name,
                to_char(pdatlistdateout, 'yyyy-mm-dd hh24:mi:ss')      as list_date,
                pistatusout                                            as status,
                to_char(pdatprocesseddateout, 'yyyy-mm-dd hh24:mi:ss') as processed_date,
                pilistcntout                                           as list_cnt,
                piprocessedcntout                                      as processed_cnt,
                piaddcntout                                            as add_cnt,
                pieditcntout                                           as edit_cnt,
                pidelcntout                                            as del_cnt,
                pierrcntout                                            as err_cnt,
                piwarncntout                                           as warn_cnt,
                pcerrinfoout                                           as err_info
            from cyberft.p_import_process_import(:piImport)
        },
        {
            piImport  => $params->{Import},
        },
        {
            mail           => 'Mail',
            request_type   => 'RequestType',
            file_name      => 'FileName',
            list_date      => 'ListDate',
            status         => 'Status',
            processed_date => 'ProcessedDate',
            list_cnt       => 'ListCnt',
            processed_cnt  => 'ProcessedCnt',
            add_cnt        => 'AddCnt',
            edit_cnt       => 'EditCnt',
            del_cnt        => 'DelCnt',
            err_cnt        => 'ErrCnt',
            warn_cnt       => 'WarnCnt',
            err_info       => 'ErrInfo',
        }
    );
}

sub get_sys_params {
    my $self = shift;
    return undef unless ($self->{dbh});
    my $data = $self->{dbh}->selectall_arrayref('select par_code, par_value from cyberft.w_sys_params', {Slice => {}});
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
                from cyberft.w_messages
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
    return $self->execute_db_api_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pirateout as id
            from cyberft.p_rate_api_set(
                :pcCurrCode,  -- код валюты (символьный, например - USD)
                :pnRate,      -- значение курса
                to_date(:pdatRateDate, 'yyyy-mm-dd')
            )
        },
        {
            pcCurrCode   => $params->{CurrCode},
            pnRate       => $params->{Rate},
            pdatRateDate => $params->{RateDate},
        },
        {
            id => 'RateId',
        }
    );
}

sub read_lob {
    my ($self, $lob_oid, $fh, $timeout) = @_;

    my $BLOCK_SIZE = 1000000;

    my $dbh = $self->dbh;
    local $dbh->{AutoCommit} = 0;

    my $result;
    eval {
        local $SIG{ALRM} = sub { die 'TIMEOUT' };
        $result = eval {
            alarm $timeout || 0;

            my $lob_fd = $dbh->pg_lo_open($lob_oid, $dbh->{pg_INV_READ});
            return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot open lob: ' . $dbh->errstr }
                unless defined($lob_fd);

            my $buffer = 0;
            my $length = 0;
            while (my $bytes_read = $dbh->pg_lo_read($lob_fd, $buffer, $BLOCK_SIZE)) {
                print $fh $buffer;
                $length += $bytes_read;
            }

            $dbh->pg_lo_close($lob_fd);

            return { Result => 0, ErrCode => 0, ErrMsg => '', Length => $length };
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

sub create_lob {
    my ($self, $fh) = @_;

    my $BLOCK_SIZE = 1000000;

    my $dbh = $self->dbh;
    local $dbh->{AutoCommit} = 0;

    my $lob_oid = $dbh->pg_lo_creat($dbh->{pg_INV_WRITE});
    return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot create lob: ' . $dbh->errstr }
        unless defined $lob_oid;

    my $lob_fd = $dbh->pg_lo_open($lob_oid, $dbh->{pg_INV_WRITE});
    return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot open lob for writing: ' . $dbh->errstr }
        unless defined $lob_fd;

    my $buffer;
    while (my $bytes_read = read($fh, $buffer, $BLOCK_SIZE)) {
        my $bytes_written = $dbh->pg_lo_write($lob_fd, $buffer, $bytes_read);
        return { Result => -1, ErrCode => -1, ErrMsg => 'Lob writing failed: ' . $dbh->errstr }
            unless defined($bytes_written);
    }

    $dbh->pg_lo_close($lob_fd);

    return { Result => 0, ErrCode => 0, ErrMsg => '', LobOid => $lob_oid };
}

sub get_lob_size {
    my ($self, $lob_oid) = @_;
    my $row = $self->dbh->selectcol_arrayref('select cyberft.get_lo_size(?)', {}, $lob_oid);

    return $row->[0];
}

sub execute_db_api_function {
    my ($self, $query, $in_params, $out_params_mapping) = @_;

    unless ($self->{dbh}) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Database not connected' };
    }

    my ($sth, $err) = $self->prepare($query);
    if (defined $err) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot prepare db query: ' . $err };
    }

    if ($in_params) {
        foreach my $param_key (keys %$in_params) {
            $sth->bind_param(":$param_key", $in_params->{$param_key});
        }
    }

    my $res = $sth->execute();
    unless ($res) {
        return { Result => -1, ErrCode => -1, ErrMsg => 'Cannot execute db query: ' . $sth->errstr };
    }

    if (my $row = $sth->fetchrow_hashref) {
        my $result = {
            Result  => $row->{has_error} ? -1 : 0,
            ErrCode => $row->{error_code},
            ErrMsg  => $row->{has_error} ? $row->{error_message} : 'Success',
        };

        if (!$row->{has_error} && $out_params_mapping) {
            foreach my $key_from (keys %$out_params_mapping) {
                my $key_to = $out_params_mapping->{$key_from};
                $result->{$key_to} = $row->{$key_from};
            }
        }

        return $result;
    }

    return { Result => -1, ErrCode => -1, ErrMsg => 'Database query has not returned any results' };
}

1;