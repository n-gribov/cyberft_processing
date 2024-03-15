package CyberFT::Errors;
use base 'Exporter';

use strict;
use utf8;
use Encode;
use Data::Dumper;


our @EXPORT = qw{
    ERR_LEVEL_EMERGENCY
    ERR_LEVEL_ALERT
    ERR_LEVEL_ERROR
    ERR_LEVEL_WARNING
    ERR_LEVEL_NOTICE
    ERR_LEVEL_INFORMATIONAL
    ERR_LEVEL_DEBUG

    ERR_TYPE_APPLICATION
    ERR_TYPE_TRANSPORT
    ERR_TYPE_DOCUMENT

    ERR_PROCESSING
    ERR_BROKER_CONNECTION
    ERR_DATABASE
    ERR_INPUT_FILE_NOT_FOUND
    ERR_FILE_ACCESS
    ERR_MAX_ENVELOPE_SIZE
    ERR_ENVELOPE_PARSE
    ERR_SIGNATURE_CHECK
    ERR_SIGNATURE_INJECT
    ERR_VALIDATE_PAYREGINFO
    ERR_VALIDATE_VALIDUNTIL
    ERR_TIMELIMIT_EXPIRED
    ERR_RECV_FRAGMENT_SUPPORT
    ERR_MSG_ENQUEUE_LOCAL
    ERR_MSG_ENQUEUE_REMOTE
    ERR_SAVE_MESSAGE
    ERR_SAVE_MESSAGE_STATUS
    ERR_ADD_MESSAGE_CERT
    ERR_SAVE_STATUS_REPORT
    ERR_SEND_ACK
    ERR_BROKER_RECV
    ERR_GET_UNSENT
    ERR_DOCTYPE_PROCESS
    ERR_BICDIR_UNKNOWN_TYPE
    ERR_BICDIR_FILE_MISSING
    ERR_SAVE_REPLY_BICDIR
    ERR_IMPORT_BICDIR
    ERR_REQUEST_BICDIR
    ERR_EXPORT_BICDIR
    ERR_RECV_ACKS
    ERR_CHECK_ACKS
    ERR_RECIPIENT_REJECTION
};

use constant {
    ERR_LEVEL_EMERGENCY        => 1,
    ERR_LEVEL_ALERT            => 2,
    ERR_LEVEL_ERROR            => 3,
    ERR_LEVEL_WARNING          => 4,
    ERR_LEVEL_NOTICE           => 5,
    ERR_LEVEL_INFORMATIONAL    => 6,
    ERR_LEVEL_DEBUG            => 7,

    ERR_TYPE_APPLICATION       => 1,
    ERR_TYPE_TRANSPORT         => 2,
    ERR_TYPE_DOCUMENT          => 3,

    ERR_PROCESSING             => 700,
    ERR_BROKER_CONNECTION      => 701,
    ERR_DATABASE               => 702,
    ERR_INPUT_FILE_NOT_FOUND   => 703,
    ERR_FILE_ACCESS            => 704,
    ERR_MAX_ENVELOPE_SIZE      => 705,
    ERR_ENVELOPE_PARSE         => 706,
    ERR_SIGNATURE_CHECK        => 707,
    ERR_SIGNATURE_INJECT       => 708,
    ERR_VALIDATE_PAYREGINFO    => 709,
    ERR_VALIDATE_VALIDUNTIL    => 710,
    ERR_TIMELIMIT_EXPIRED      => 711,
    ERR_RECV_FRAGMENT_SUPPORT  => 712,
    ERR_MSG_ENQUEUE_LOCAL      => 713,
    ERR_MSG_ENQUEUE_REMOTE     => 714,
    ERR_SAVE_MESSAGE           => 715,
    ERR_SAVE_MESSAGE_STATUS    => 716,
    ERR_ADD_MESSAGE_CERT       => 717,
    ERR_SAVE_STATUS_REPORT     => 718,
    ERR_SEND_ACK               => 719,
    ERR_BROKER_RECV            => 720,
    ERR_GET_UNSENT             => 721,
    ERR_DOCTYPE_PROCESS        => 722,
    ERR_BICDIR_UNKNOWN_TYPE    => 723,
    ERR_BICDIR_FILE_MISSING    => 724,
    ERR_SAVE_REPLY_BICDIR      => 725,
    ERR_IMPORT_BICDIR          => 726,
    ERR_REQUEST_BICDIR         => 727,
    ERR_EXPORT_BICDIR          => 728,
    ERR_RECV_ACKS              => 729,
    ERR_CHECK_ACKS             => 730,
    ERR_RECIPIENT_REJECTION    => 731,
};

our $ErrorTypes = {
    ERR_TYPE_APPLICATION() => "Ошибка приложения",
    ERR_TYPE_TRANSPORT()   => "Ошибка транспорта",
    ERR_TYPE_DOCUMENT()    => "Ошибка обработки документа",
};

our $Errors = {
    ERR_PROCESSING() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Ошибка процессинга',
        msg    => 'Ошибка процессинга',
        params => [],
    },
    ERR_BROKER_CONNECTION() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Ошибка соединения с брокером сообщений',
        msg    => 'Ошибка соединения с брокером сообщений',
        params => [],
    },
    ERR_DATABASE() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Ошибка базы данных',
        msg    => 'Ошибка базы данных',
        params => [],
    },
    ERR_INPUT_FILE_NOT_FOUND() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Входящий документ не найден',
        msg    => 'Ошибка при обработке документа %1: Входящий документ не найден',
        params => ['Обрабатываемый документ'],
    },
    ERR_FILE_ACCESS() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Документ недоступен',
        msg    => 'Ошибка при обработке документа %1: Документ недоступен',
        params => ['Обрабатываемый документ'],
    },
    ERR_MAX_ENVELOPE_SIZE() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Превышен максимальный размер XML-конверта',
        msg    => 'Ошибка при обработке документа %1: Превышен максимальный размер XML-конверта: %2',
        params => ['Обрабатываемый документ', 'Размер XML-конверта'],
    },
    ERR_ENVELOPE_PARSE() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Ошибка формата XML-конверта',
        msg    => 'Ошибка при обработке документа %1: Ошибка формата XML-конверта: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_SIGNATURE_CHECK() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Ошибка проверки подписи',
        msg    => 'Ошибка при обработке документа %1: Ошибка проверки подписи: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_SIGNATURE_INJECT() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Ошибка добавления подписи к документу',
        msg    => 'Ошибка при обработке документа %1: Ошибка добавления подписи к документу',
        params => ['Обрабатываемый документ'],
    },
    ERR_VALIDATE_PAYREGINFO() => {
        type  => ERR_TYPE_DOCUMENT,
        lvl   => ERR_LEVEL_WARNING,
        desc  => 'Некорректные значения в разделе PaymentRegisterInfo',
        msg   => 'Ошибка при обработке документа %1: Некорректные значения в разделе PaymentRegisterInfo',
        params => ['Обрабатываемый документ'],
    },
    ERR_VALIDATE_VALIDUNTIL() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Некорректное значение параметра ValidUntil',
        msg    => 'Ошибка при обработке документа %1: Некорректное значение параметра ValidUntil: %2',
        params => ['Обрабатываемый документ', 'Значение ValidUntil'],
    },
    ERR_TIMELIMIT_EXPIRED() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Контрольное время доставки документа истекло',
        msg    => 'Ошибка при обработке документа %1: Контрольное время доставки документа истекло: %2',
        params => ['Обрабатываемый документ', 'Контрольное время доставки документа'],
    },
    ERR_RECV_FRAGMENT_SUPPORT() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Получатель не поддерживает фрагментированную загрузку больших документов',
        msg    => 'Ошибка при обработке документа %1: Получатель не поддерживает фрагментированную загрузку больших документов: %2',
        params => ['Обрабатываемый документ', 'Получатель'],
    },
    ERR_MSG_ENQUEUE_LOCAL() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось добавить документ в очередь локального брокера сообщений',
        msg    => 'Ошибка при обработке документа %1: Не удалось добавить документ в очередь локального брокера сообщений: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_MSG_ENQUEUE_REMOTE() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось добавить документ в очередь удаленного брокера сообщений',
        msg    => 'Ошибка при обработке документа %1: Не удалось добавить документ в очередь удаленного брокера сообщений: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_SAVE_MESSAGE() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось сохранить документ',
        msg    => 'Ошибка при обработке документа %1: Не удалось сохранить документ: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_SAVE_MESSAGE_STATUS() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось изменить статус документа',
        msg    => 'Ошибка при обработке документа %1: Не удалось изменить статус документа %2: %3',
        params => ['Обрабатываемый документ', 'Документ, статус которого изменяется', 'Причина ошибки'],
    },
    ERR_ADD_MESSAGE_CERT() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось добавить сертификат к документу',
        msg    => 'Ошибка при обработке документа %1: Не удалось добавить сертификат к документу (%2): %3',
        params => ['Обрабатываемый документ', 'Отпечаток сертификата', 'Причина ошибки'],
    },
    ERR_SAVE_STATUS_REPORT() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось сохранить ответный документ StatusReport',
        msg    => 'Ошибка при обработке документа %1: Не удалось сохранить ответный документ StatusReport: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_SEND_ACK() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось добавить CFTAck/CFTResend в очередь брокера сообщений',
        msg    => 'Ошибка при обработке документа %1: Не удалось добавить CFTAck/CFTResend в очередь брокера сообщений',
        params => ['Обрабатываемый документ'],
    },
    ERR_BROKER_RECV() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Не удалось получить следующий документ из очереди брокера сообщений',
        msg    => 'Не удалось получить следующий документ из очереди брокера сообщений',
        params => [],
    },
    ERR_GET_UNSENT() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_ERROR,
        desc   => 'Не удалось получить следующий неотправленный документ из базы данных',
        msg    => 'Не удалось получить следующий неотправленный документ из базы данных',
        params => [],
    },
    ERR_DOCTYPE_PROCESS() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Некорректный тип документа для обработки процессингом',
        msg    => 'Ошибка при обработке документа %1: Некорректный тип документа для обработки процессингом: %2',
        params => ['Обрабатываемый документ', 'Тип документа'],
    },
    ERR_BICDIR_UNKNOWN_TYPE() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Запрошен неизвестный тип обновления',
        msg    => 'Ошибка при обработке документа %1: Запрошен неизвестный тип обновления',
        params => ['Обрабатываемый документ'],
    },
    ERR_BICDIR_FILE_MISSING() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Запрошенный файл отсутствует',
        msg    => 'Ошибка при обработке документа %1: Запрошенный файл отсутствует',
        params => ['Обрабатываемый документ'],
    },
    ERR_SAVE_REPLY_BICDIR() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось сохранить ответный документ BICDir',
        msg    => 'Ошибка при обработке документа %1: Не удалось сохранить ответный документ BICDir: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_IMPORT_BICDIR() => {
        type   => ERR_TYPE_DOCUMENT,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось импортировать обновление BICDir',
        msg    => 'Ошибка при обработке документа %1: Не удалось импортировать обновление BICDir: %2',
        params => ['Обрабатываемый документ', 'Причина ошибки'],
    },
    ERR_REQUEST_BICDIR() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось отправить запрос обновления BICDir',
        msg    => 'Не удалось отправить запрос обновления BICDir: %1',
        params => ['Причина ошибки'],
    },
    ERR_EXPORT_BICDIR() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Не удалось экспортировать обновление BICDir',
        msg    => 'Не удалось экспортировать обновление BICDir (%1): %2',
        params => ['Тип экспорта', 'Причина ошибки'],
    },
    ERR_RECV_ACKS() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Ошибка получения технических сообщений от внешних процессингов',
        msg    => 'Ошибка получения технических сообщений от внешних процессингов: %1',
        params => ['Причина ошибки'],
    },
    ERR_CHECK_ACKS() => {
        type   => ERR_TYPE_APPLICATION,
        lvl    => ERR_LEVEL_WARNING,
        desc   => 'Ошибка запроса статусов доставки документов',
        msg    => 'Ошибка запроса статусов доставки документов: %1',
        params => ['Причина ошибки'],
    },
    ERR_RECIPIENT_REJECTION() => {
        type   => ERR_TYPE_TRANSPORT,
        lvl    => ERR_LEVEL_INFORMATIONAL,
        desc   => 'Отказ получателя',
        msg    => 'Получатель прислал StatusReport с отказом. Ошибка: %1, %2',
        params => ['Код ошибки', 'Описание ошибки'],
    },
};

for my $num (keys %$Errors) {
    $Errors->{$num}->{num} = $num;
}

sub type_name {
    my ($type) = @_;
    return $ErrorTypes->{$type};
}

sub info {
    my ($error_num) = @_;
    return $Errors->{$error_num};
}

sub type {
    my ($error_num) = @_;
    return $Errors->{$error_num}->{type};
}

sub lvl {
    my ($error_num) = @_;
    return $Errors->{$error_num}->{lvl};
}

sub desc {
    my ($error_num) = @_;
    return $Errors->{$error_num}->{desc};
}

sub msg {
    my ($error_num, $param1, $param2, $param3) = @_;
    my $msg = $Errors->{$error_num}->{msg};
    $msg =~ s/%1/$param1/g if defined($param1);
    $msg =~ s/%2/$param2/g if defined($param2);
    $msg =~ s/%3/$param3/g if defined($param3);
    return $msg;
}

1;