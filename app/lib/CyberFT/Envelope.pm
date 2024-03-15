# Класс для работы с конвертом CyberXML

package CyberFT::Envelope;

use strict;
use utf8;
use Data::Dumper;
use File::Spec ();
use XML::LibXML ();
use MIME::Base64 ();
use Data::UUID ();
use Crypt::OpenSSL::RSA ();
use Crypt::OpenSSL::X509 ();
use Encode ();
use POSIX qw(strftime);
use xmldsig ();

use CyberFT::Utils qw(
    escape_crlf
    remove_crlf
    dumper
);

# XSD схема
our $Schema = _load_xsd('CyberFT_DocEnvelope.xsd');

# Метод разбирает XML-конверт и достаёт необходимые параметры
#   xml_string - содержимое XML
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан)
#   skip_validation - пропустить валидацию по xsd-схеме (опциональный логический параметр)
sub parse {
	# Получить список входных параметров
    my %params = @_;
	# Если не заданы необходимые параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }

    # Распарсить документ
    my $doc;
    eval {
		# Если загрузка из строки
        if () {
            $doc = XML::LibXML->load_xml(
                string => $params{xml_string},
                huge => 1,
            );
        } else {
			# Если загрузка из файла
            $doc = XML::LibXML->load_xml(
                location => $params{xml_file},
                huge => 1,
            );
        }
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Строка ошибки
        my $errstr = "XML parse error";
		# Если ошибка это объект и есть поле domain, равное parser
        if (ref($err) && $err->domain eq "parser") {
			# К строке ошибки добавляется сообщение из err
            $errstr .= ": " . $err->message;
            $errstr =~ s/\r|\n/ /g;
        }
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => $errstr};
    }

    # Валидируем по xsd-схеме, если нужно
    unless ($params{skip_validation}) {
        eval {
			# Создать объект схемы
            my $schema = XML::LibXML::Schema->new(string => $Schema);
			# Валидировать
            $schema->validate($doc);
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Строка ошибки
            my $errstr = "XML validation against the XSD schema failed";
			# Если ошибка это объект и есть поле domain, равное Schemas validity
            if (ref($err) && $err->domain eq "Schemas validity") {
				# К строке ошибки добавляется сообщение из err
                $errstr .= ": " . $err->message;
                $errstr =~ s/\r|\n/ /g;
            }
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => $errstr};
        }
    }

	# Конверт
    my $envelope = {};

    # Пути к различным параметрам сообщения
    my $fields_xpath = {
        DocId         => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocId']},
        DocDate       => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocDate']},
        SenderId      => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='SenderId']},
        ReceiverId    => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='ReceiverId']},
        DocType       => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocType']},
        ValidUntil    => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='ValidUntil']},
        PayInfo_count => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocDetails']/*[local-name()='PaymentRegisterInfo']/@count},
        PayInfo_cur   => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocDetails']/*[local-name()='PaymentRegisterInfo']/@cur},
        PayInfo_sum   => q{/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='DocDetails']/*[local-name()='PaymentRegisterInfo']/@sum},
    };

	# Перебирать пути и искать их в XML
    for my $field (keys %$fields_xpath) {
        my $xpath = $fields_xpath->{$field};
		# Найти содерожимое узла по пути
        $envelope->{$field} = _get_xpath_value($doc, $xpath);
		# Если найдено, добавить значение в конверт
        if (defined $envelope->{$field}) {
            $envelope->{$field} =~ s/^\s*|\s*$//g;
        }
    }

    # Дополнительные параметры для некоторых типов докуметов
    my $add_fields_xpath = {};
	# Если документ CFTAck
    if ($envelope->{DocType} eq 'CFTAck') {
        $add_fields_xpath = {
            Ack_RefDocId    => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='Ack']/*[local-name()='RefDocId']},
            Ack_RefSenderId => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='Ack']/*[local-name()='RefSenderId']},
        };
    }
	# Если документ CFTChkAck
    elsif ($envelope->{DocType} eq 'CFTChkAck') {
        $add_fields_xpath = {
            ChkAck_RefDocId    => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='ChkAck']/*[local-name()='RefDocId']},
            ChkAck_RefSenderId => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='ChkAck']/*[local-name()='RefSenderId']},
        };
    }
	# Если документ CFTResend
    elsif ($envelope->{DocType} eq 'CFTResend') {
        $add_fields_xpath = {
            Resend_RefDocId    => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='Resend']/*[local-name()='RefDocId']},
            Resend_RefSenderId => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='Resend']/*[local-name()='RefSenderId']},
        };
    }
	# Если документ CFTStatusReport
    elsif ($envelope->{DocType} eq 'CFTStatusReport') {
        $add_fields_xpath = {
            StatusReport_RefDocId   => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='StatusReport']/*[local-name()='RefDocId']},
            StatusReport_StatusCode => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='StatusReport']/*[local-name()='StatusCode']},
            StatusReport_ErrorCode => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='StatusReport']/*[local-name()='ErrorCode']},
            StatusReport_ErrorDescription => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='StatusReport']/*[local-name()='ErrorDescription']},
        };
    }
	# Если документ BICDirRequest
    elsif ($envelope->{DocType} eq 'BICDirRequest') {
        $add_fields_xpath = {
            BICDirReq_Full_ContentFormat   => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='FullLoadRequest']/*[local-name()='ContentFormat']},
            BICDirReq_Full_LastUpdateDate  => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='FullLoadRequest']/*[local-name()='LastUpdateDate']},
            BICDirReq_Full_SkipIfUnchanged => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='FullLoadRequest']/*[local-name()='SkipIfUnchanged']},
            BICDirReq_Incr_ContentFormat   => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='IncrementLoadRequest']/*[local-name()='ContentFormat']},
            BICDirReq_Incr_StartDate       => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='IncrementLoadRequest']/*[local-name()='StartDate']},
            BICDirReq_Incr_EndDate         => q{/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdateRequest']/*[local-name()='IncrementLoadRequest']/*[local-name()='EndDate']},
        };
    };

	# Перебрать дополнительные параметры
    for my $field (keys %$add_fields_xpath) {
        my $xpath = $add_fields_xpath->{$field};
		# Найти значение узла по пути
        $envelope->{$field} = _get_xpath_value($doc, $xpath);
		# Если найдено, лдобавить в конверт
        if (defined $envelope->{$field}) {
            $envelope->{$field} =~ s/^\s*|\s*$//g;
        }
    }

    # Список подписей
    my $signatures = [];
	# Список контейнеров подписей
    my $sig_cont_nodes;
    eval {
		# Получить все контеёнеры подписей из документа
        $sig_cont_nodes = $doc->findnodes("/*[local-name()='Document']/*[local-name()='Header']/*[local-name()='SignatureContainer']");
    };
	# Если контейнеры не найдены, сделать пустой список
    $sig_cont_nodes = [] unless (defined $sig_cont_nodes);
	# Перебрать список контейнеров
    for my $sig_cont_node (@$sig_cont_nodes) {
		# Объект подписи
        my $sig = {};
        eval {
            my $sig_node;
			# Найти подписи в контейнере
            $sig_node = $sig_cont_node->findnodes(q{*[local-name()='Signature']})->[0];
			# Если найдена подпись
            if ($sig_node) {
				# Добавить в объект подписи путь и фингерпринт
                $sig->{SignaturePath} = Encode::encode_utf8($sig_node->nodePath());
                $sig->{FingerPrint} = _get_xpath_value($sig_node, "*[local-name()='KeyInfo']/*[local-name()='KeyName']");
				# Определить неймспейс
                my ($ns) = $sig_node->toString =~ /(<Signature[^>]+>)/;
				# Если неймспейс содержит cftsign, присвоить тип подписи cftsign
                if ($ns =~ /cftsign/) {
                    $sig->{Type} = 'cftsign';
                    $sig->{SignatureValue} = _get_xpath_value($sig_node, "*[local-name()='SignatureValue']");
                }
				# Если неймспейс сожержит xmldsig, присвоить тип подписи xmldsig
                elsif ($ns =~ /xmldsig/) {
                    $sig->{Type} = 'xmldsig';
                }
            }
        };
		# Если не присвоен тим подписи, присвоить unknown
        unless (defined $sig->{Type}) {
            $sig->{Type} = 'unknown';
        }
		# Добавить подпись в список подписей
        push @$signatures, $sig;
    }
	# Добавить список подписей в конверт
    $envelope->{Signatures} = $signatures;

    # Список информаци о TraceList
    my $trace_list = [];
    my $trace_nodes;
	# Найти узлы Trace
    eval {
        $trace_nodes = $doc->findnodes("/*[local-name()='Document']/*[local-name()='TraceList']/*[local-name()='Trace']");
    };
	# Если не найдены, сделать пустой список
    $trace_nodes = [] unless (defined $trace_nodes);
	# Перебрать список
    for my $trace_node (@$trace_nodes) {
		# Объект трейса
        my $t = {};
		# Присвоить объекту поля, полученные из узла Trace
        eval {
            $t->{Date} = _get_xpath_value($trace_node, "*[local-name()='Date']");
            $t->{SignerId} = _get_xpath_value($trace_node, "*[local-name()='SignerId']");
            $t->{SenderId} = _get_xpath_value($trace_node, "*[local-name()='ReceivedFrom']/*[local-name()='SenderId']");
            $t->{SenderIP} = _get_xpath_value($trace_node, "*[local-name()='ReceivedFrom']/*[local-name()='SenderIP']");
            $t->{ReceiverId} = _get_xpath_value($trace_node, "*[local-name()='SendingTo']/*[local-name()='ReceiverId']");
            $t->{ReceiverIP} = _get_xpath_value($trace_node, "*[local-name()='SendingTo']/*[local-name()='ReceiverIP']");
			# Узел подписи
            my $sig_node;
			# Найти подпись
            $sig_node = $trace_node->findnodes(q{*[local-name()='SignatureContainer']/*[local-name()='Signature']})->[0];
			# Если найдена, добавить в объект трейса путь и фингерпринт подписи
            if ($sig_node) {
                $t->{SignaturePath} = Encode::encode_utf8($sig_node->nodePath());
                $t->{FingerPrint} = _get_xpath_value($sig_node, "*[local-name()='KeyInfo']/*[local-name()='KeyName']");
            }
        };
		# Добавить трейс в список
        push @$trace_list, $t;
    }
	# Добавить список трейсов в конверт
    $envelope->{TraceList} = $trace_list;
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', Envelope => $envelope};
}

# Метод разбирает XML-конверт и достаёт необходимые параметры обновлений BICDir
#   xml_string - содержимое XML
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан)
sub parse_bicdir {
	# Получить список входных параметров
    my %params = @_;
	# Если не переданы входные параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }

    # Распарсить документ
    my $doc;
    eval {
		# Если указан параметр строки XML
        if (defined $params{xml_string}) {
			# Загрузить документ из строки
            $doc = XML::LibXML->load_xml(
                string => $params{xml_string},
                huge => 1,
            );
        } else {
			# Загрузить документ из файла
            $doc = XML::LibXML->load_xml(
                location => $params{xml_file},
                huge => 1,
            );
        }
    };
	# Если возникла ошибка
    if (my $err = $@) {
        # Строка ошибки
		my $errstr = "XML parse error";
		# Если ошибка это объект и сесть поле domain
        if (ref($err) && $err->domain eq "parser") {
			# Добавить тест ошибки в строку ошибки
            $errstr .= ": " . $err->message;
            $errstr =~ s/\r|\n/ /g;
        }
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => $errstr};
    }
	# Список bicdir
    my $bicdirs = {
        FullUpdate => undef,
        IncrementUpdates => undef,
    };

    my $nodes = undef;
	# Получить узлы с полным обновлением bicdir
    eval {
        $nodes = $doc->findnodes("/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdate']/*[local-name()='FullLoad']");
    };
	# Если получены узлы
    if (defined $nodes && scalar @$nodes > 0) {
		# Первый узел
        my $node = $nodes->[0];
        eval {
			# Объект обновления bicdir
            my $upd = {};
			# Заполнить поля объекта значениями из узла
            $upd->{LastUpdateDate} = _get_xpath_value($node, q{*[local-name()='Header']/*[local-name()='LastUpdateDate']});
            $upd->{ReqCount} = _get_xpath_value($node, q{*[local-name()='Header']/*[local-name()='ReqCount']});
            $upd->{Format} = _get_xpath_value($node, q{*[local-name()='Content']/@format});
            $upd->{Charset} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@charSet});
            $upd->{Filename} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@filename});
            $upd->{Encoding} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@encoding});
            $upd->{RawData} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']});
			# Поместить объект в список по ключу FullUpdate
            $bicdirs->{FullUpdate} = $upd;
        };
    }

    $nodes = undef;
	# Получить узлы с частичным обновлением bicdir
    eval {
        $nodes = $doc->findnodes("/*[local-name()='Document']/*[local-name()='Body']/*[local-name()='BICDirectoryUpdate']/*[local-name()='IncrementLoad']");
    };
	# Если получены узлы
    if (defined $nodes && scalar @$nodes > 0) {
		# Создать пустой список для накопления обновлений
        $bicdirs->{IncrementUpdates} = [];
		# Перебрать найденные узлы
        for my $node (@$nodes) {
            eval {
				# Объект обновления bicdir
    	        my $upd = {};
				# Заполнить поля объекта значениями из узла
                $upd->{StartDate} = _get_xpath_value($node, q{*[local-name()='Header']/*[local-name()='StartDate']});
                $upd->{EndDate} = _get_xpath_value($node, q{*[local-name()='Header']/*[local-name()='StartDate']});
                $upd->{ReqCount} = _get_xpath_value($node, q{*[local-name()='Header']/*[local-name()='ReqCount']});
                $upd->{Format} = _get_xpath_value($node, q{*[local-name()='Content']/@format});
                $upd->{Charset} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@charSet});
                $upd->{Filename} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@filename});
                $upd->{Encoding} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']/@encoding});
                $upd->{RawData} = _get_xpath_value($node, q{*[local-name()='Content']/*[local-name()='RawData']});
				# Поместить объект в список по ключу IncrementUpdates
                push @{$bicdirs->{IncrementUpdates}}, $upd;
            };
        }
    }
	# Если найдено полное обновление
    if (defined $bicdirs->{FullUpdate}) {
		# Обхъект обновления
        my $upd = $bicdirs->{FullUpdate};
		# Убрать первый и последний пробелы в счётчике записей
        $upd->{ReqCount} =~ s/^\s*|\s*$//g;
		# Если счётчик записей состоит не из цифр
        unless ($upd->{ReqCount} =~ /^\d+$/) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Bad ReqCount value"};
        }
		# Убрать первый и последний пробелы в дате оюбновления
        $upd->{LastUpdateDate} =~ s/^\s*|\s*$//g;
		# Если дата не соответствует формату
        unless ($upd->{LastUpdateDate} =~ /^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d/) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "Bad LastUpdateDate value"};
        }
    }
	# Если найдены частичные обновления
    if (defined $bicdirs->{IncrementUpdates}) {
		# Перебрать все частичные обновления
        for my $upd (@{$bicdirs->{IncrementUpdates}}){
			# Убрать первый и последний пробелы в счётчике записей
    	    $upd->{ReqCount} =~ s/^\s*|\s*$//g;
			# Если счётчик записей состоит не из цифр
            unless ($upd->{ReqCount} =~ /^\d+$/) {
				# Вернуть результат с ошибкой
                return {Result => 1, ErrCode => 10, ErrMsg => "Bad ReqCount value"};
            }
        }
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', BICDir => $bicdirs};
}

# Метод добавляет в раздел TraceList xml-конверта подписанную запись Trace
#   xml_string - содержимое XML
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан)
#   date, signer_id, sender_id, sender_ip, receiver_id, receiver_ip,
#   cert_subject, cert_fingerprint, cert_file, pkey_file, pkey_pwd.
sub inject_trace_sign {
	# Получить список входных параметров
    my %params = @_;
	# Если не указаны входные параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }
	# Вставить трейс с параметрами
    my $r_inj = inject_trace(
        xml_string       => $params{xml_string},
        xml_file         => $params{xml_file},
        date             => $params{date},
        signer_id        => $params{signer_id},
        sender_id        => $params{sender_id},
        sender_ip        => $params{sender_ip},
        receiver_id      => $params{receiver_id},
        receiver_ip      => $params{receiver_ip},
        cert_subject     => $params{cert_subject},
        cert_fingerprint => $params{cert_fingerprint},
    );
	# Если результат вставки не 0
    if ($r_inj->{Result} ne '0') {
		# Вернуть результат
        return $r_inj;
    }
	# Строка для вставки в XML 
    my $xml_string_inj = undef;
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
		# Сформировать строку для вставки из поля XML результата
        $xml_string_inj = $r_inj->{XML};
    }
	# Подписать строку для вставки в XML
    my $r_sig = sign(
        xml_string => $xml_string_inj,
        xml_file   => $params{xml_file},
        sigpath    => $r_inj->{SigPath},
        cert_file  => $params{cert_file},
        pkey_file  => $params{pkey_file},
        pkey_pwd   => $params{pkey_pwd},
    );
	# Если результат подлписания не 0
    if ($r_sig->{Result} ne '0') {
		# Вернуть результат
        return $r_sig;
    }

    my $xml = undef;
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
		# Получить xml из поля XML результата
        $xml = $r_sig->{XML};
    }
	# Вернуть успешный результат, поджписанный XML, путь к подписи и трейс ид
    return {
        Result  => 0,
        ErrCode => 0,
        ErrMsg  => '',
        XML     => $xml,
        SigPath => $r_inj->{SigPath},
        TraceId => $r_inj->{TraceId}
    };
}

# Метод добавляет в раздел TraceList шаблон для подписи xmldsig
#   xml_string - содержимое XML
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан)
#   date, signer_id, sender_id, sender_ip, receiver_id, receiver_ip,
#   cert_subject, cert_fingerprint.
sub inject_trace {
	# Получить список входных параметров
    my %params = @_;
	# Если не указаны входные параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }

    # Распарсить документ
    my $doc;
    eval {
		# Если указан параметр строки XML
        if (defined $params{xml_string}) {
			# Загрузщить документ из строки XML
            $doc = XML::LibXML->load_xml(
                string => $params{xml_string},
                huge => 1,
            );
        } else {
			# Загрузить документ из файла
            $doc = XML::LibXML->load_xml(
                location => $params{xml_file},
                huge => 1,
            );
        }
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Строка ошибки
        my $errstr = "XML parse error";
		#  Если ошибка это объекти и есть поле domain
        if (ref($err) && $err->domain eq "parser") {
			# Добавить к строке текст ошибки
            $errstr .= ": " . $err->message;
            $errstr =~ s/\r|\n/ /g;
        }
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => $errstr};
    }

	# Дата берётся из входныз параметров либо текущая
    my $date = (defined $params{date}) ? $params{date} : _timestamp();
	# Создать новый трейс ид с помощью UUID
    my $trace_id = 'traceId_' . lc(Data::UUID->new->create_str());
	# Удалить дефисы из трейс ид
    $trace_id =~ s/-//g;
	# Шаблон подписи
    my $template;
    $template .= q{<Trace Id="} . $trace_id . q{">};
    $template .= q{<Date>}.$date.q{</Date>};
    $template .= q{<SignerId>}.$params{signer_id}.q{</SignerId>};
    $template .= q{<ReceivedFrom>};
    $template .= q{<SenderId>}.$params{sender_id}.q{</SenderId>};
    $template .= q{<SenderIP>}.$params{sender_ip}.q{</SenderIP>};
    $template .= q{</ReceivedFrom>};
    $template .= q{<SendingTo>};
    $template .= q{<ReceiverId>}.$params{receiver_id}.q{</ReceiverId>};
    $template .= q{<ReceiverIP>}.$params{receiver_ip}.q{</ReceiverIP>} if (defined $params{receiver_ip});
    $template .= q{</SendingTo>};
    $template .= q{<SignatureContainer>};
    $template .= q{<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">};
    $template .= q{<SignedInfo>};
    $template .= q{<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>};
    $template .= q{<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>};
    $template .= q{<Reference URI="">};
    $template .= q{<Transforms>};
    $template .= q{<Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">};
    $template .= q{<XPath xmlns:doc="http://cyberft.ru/xsd/cftdoc.01">};
    $template .= q{not(ancestor-or-self::doc:SignatureContainer or ancestor-or-self::doc:TraceList)};
    $template .= q{</XPath>};
    $template .= q{</Transform>};
    $template .= q{</Transforms>};
    $template .= q{<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>};
    $template .= q{<DigestValue></DigestValue>};
    $template .= q{</Reference>};
    $template .= q{<Reference URI="#} . $trace_id . q{">};
    $template .= q{<Transforms>};
    $template .= q{<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>};
    $template .= q{</Transforms>};
    $template .= q{<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>};
    $template .= q{<DigestValue></DigestValue>};
    $template .= q{</Reference>};
    $template .= q{</SignedInfo>};
    $template .= q{<SignatureValue></SignatureValue>};
    $template .= q{<KeyInfo>};
    $template .= q{<X509Data>};
    $template .= q{<X509SubjectName>}. $params{cert_subject} .q{</X509SubjectName>};
    $template .= q{</X509Data>};
    $template .= q{<KeyName>}. $params{cert_fingerprint} .q{</KeyName>};
    $template .= q{</KeyInfo>};
    $template .= q{</Signature>};
    $template .= q{</SignatureContainer>};
    $template .= q{</Trace>};
    my $path;
	# Создать новый XML документ
    eval {
		# Созадать парсер XML
        my $parser = XML::LibXML->new(huge => 1);
		# Распарсить шаблон в объект
        my $frag = $parser->parse_balanced_chunk($template);
		# Получить список узлов трейслиста из документа
        my $trace_list_nodes = $doc->findnodes("/*[local-name()='Document']/*[local-name()='TraceList']");
		# Если список не пуст
        if (scalar @$trace_list_nodes > 0) {
			# Получить первый узел в списке
            my $trace_list_node = $trace_list_nodes->[0];
			# Добавить в трейс-узел документа шаблон подписи
            $trace_list_node->appendChild($frag);
        } else {
			# Создать новый узел трейса
            my $trace_list_node = $doc->createElement("TraceList");
			# Добавить в него шаблон
            $trace_list_node->appendChild($frag);
			# Найти местол для вставки в документ
            my $doc_node = $doc->findnodes("/*[local-name()='Document']")->[0];
            my $body_node = $doc_node->findnodes("*[local-name()='Body']")->[0];
			# Вставить узел трейса в документ
            $doc_node->insertAfter($trace_list_node, $body_node);
        }
		# Найти трейс-узлы документа
        my $trace_nodes = $doc->findnodes("/*[local-name()='Document'][1]/*[local-name()='TraceList'][1]/*[local-name()='Trace']");
		# Количество узлов
        # my $n = scalar(@$trace_nodes);
		# Путь к добавленной подписи
        $path = q{/*[local-name()='Document']/*[local-name()='TraceList']/*[local-name()='Trace'][@Id='} . $trace_id . q{']/*[local-name()='SignatureContainer'][1]/*[local-name()='Signature'][1]};
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "Inject Trace error: $err"};
    }

    my $xml_result = undef;
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
		# Перевести документ в строку
        $xml_result = $doc->toString(0);
    } else {
		# Иначе записать документ в файл
        $doc->toFile($params{xml_file}, 0);
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', XML => $xml_result, SigPath => $path, TraceId => $trace_id};
}

# Метод подписывает xml-документ подписью xmldsig
#   xml_string - содержимое XML c шаблоном подписи,
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан),
#   sigpath    - xpath к шаблону подписи
#   cert_file  - путь к сертификату
#   pkey_file  - путь к закрытому ключу
#   pkey_pwd   - пароль к закрытому ключу
sub sign {
	# Получить список входных параметров
    my %params = @_;
	# Если не указаны входные параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }
	# Список параметров для подписи
    my $sign_params = {
            template => undef,
            sigpath  => $params{sigpath},
            cert     => $params{cert_file},
            key      => $params{pkey_file},
            pwd      => $params{pkey_pwd},
    };
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
		# Присвоить полю шаблона строку XML
        $sign_params->{template} = $params{xml_string};
    } else {
        eval {
			# Присвоить полю шаблона строку, прочитанную из файла
            CyberFT::Utils::read_file($params{xml_file}, \$sign_params->{template});
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "XML read error: $err"};
        }
    }

    my $r;
    eval {
		# Подписать с параметрами
        $r = xmldsig::sign($sign_params);
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "Sign error: $err"};
    }
	# Если результат с ошибкой
    if ($r->{result} ne '0') {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "xmldsig::sign error: ".$r->{errmsg}};
    }

    my $xml = undef;
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
        $xml = $r->{xml};
    } else {
        eval {
            CyberFT::Utils::write_file($params{xml_file}, \$r->{xml});
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "XML write error: $err"};
        }
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', XML => $xml};
}

# Метод верифицирует подпись xmldsig
#   xml_string - содержимое XML
#   xml_file   - путь к файлу с XML (если параметр xml_string не задан)
#   sigpath    - xpath к подписи
#   cert       - сертификат в виде строки
sub verify {
	# Получить список входных параметров
    my %params = @_;
	# Если не указаны входные параметры
    unless (exists $params{xml_string} || exists $params{xml_file}) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => 'Missing "xml_string" or "xml_file" parameter'};
    }
	# Параметры верификации
    my $verify_params = {
        xml     => undef,
        sigpath => $params{sigpath},
        cert    => $params{cert},
    };
	# Если указан параметр строки XML
    if (defined $params{xml_string}) {
		# Поместить строку в параметры верификации
        $verify_params->{xml} = $params{xml_string};
    } else {
		# Прочитать строку из файла и поместить в параметры верификации
        eval {
            CyberFT::Utils::read_file($params{xml_file}, \$verify_params->{xml});
        };
		# Если возникла ошибка
        if (my $err = $@) {
			# Вернуть результат с ошибкой
            return {Result => 1, ErrCode => 10, ErrMsg => "XML read error: $err"};
        }
    }

    my $r;
	# Верифицировать с параметрами
    eval {
        $r = xmldsig::verify($verify_params);
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "Verify error: $err"};
    }
	# Если результат содержит ошибку
    if ($r->{result} ne '0') {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "xmldsig::verify error: ".$r->{errmsg}};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => ''};
}

# Метод создаёт и подписывает новый XML-конверт
sub create_signed {
	# Получить список входных параметров
    my %params = @_;
	# Ид документа берётся из параметров или создаётся новый с помощью UUID
    my $doc_id = (defined $params{doc_id}) ? $params{doc_id} : Data::UUID->new->create_str();
	# Дата докуметна бьерётся из параметров или создаётся из текущей
    my $doc_date = (defined $params{doc_date}) ? $params{doc_date} : _timestamp();
	# Шаблон подписи
    my $template;
    $template .= q{<?xml version="1.0" encoding="utf-8"?>};
    $template .= q{<Document xmlns="http://cyberft.ru/xsd/cftdoc.01">};
    $template .= q{<Header>};
    $template .= q{<DocId>} . $doc_id . q{</DocId>};
    $template .= q{<DocDate>} . $doc_date . q{</DocDate>};
    $template .= q{<SenderId>} . $params{sender_id} . q{</SenderId>};
    $template .= q{<ReceiverId>} . $params{receiver_id} . q{</ReceiverId>};
    $template .= q{<DocType>} . $params{doc_type} . q{</DocType>};
    $template .= q{<ValidUntil>} . $params{valid_until} . q{</ValidUntil>} if (defined $params{valid_until});
    $template .= q{<SignatureContainer>};
    $template .= q{<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">};
    $template .= q{<SignedInfo>};
    $template .= q{<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>};
    $template .= q{<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>};
    $template .= q{<Reference URI="">};
    $template .= q{<Transforms>};
    $template .= q{<Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">};
    $template .= q{<XPath xmlns:doc="http://cyberft.ru/xsd/cftdoc.01">};
    $template .= q{not(ancestor-or-self::doc:SignatureContainer or ancestor-or-self::doc:TraceList)};
    $template .= q{</XPath>};
    $template .= q{</Transform>};
    $template .= q{</Transforms>};
    $template .= q{<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>};
    $template .= q{<DigestValue></DigestValue>};
    $template .= q{</Reference>};
    $template .= q{</SignedInfo>};
    $template .= q{<SignatureValue></SignatureValue>};
    $template .= q{<KeyInfo>};
    $template .= q{<X509Data>};
    $template .= q{<X509SubjectName>}. $params{cert_subject} .q{</X509SubjectName>};
    $template .= q{</X509Data>};
    $template .= q{<KeyName>}. $params{cert_fingerprint} .q{</KeyName>};
    $template .= q{</KeyInfo>};
    $template .= q{</Signature>};
    $template .= q{</SignatureContainer>};
    $template .= q{</Header>};

    $template .= q{<Body};
	# Если в параметрах указан mime тип
    if (defined $params{body_mime}) {
        $template .= q{ mimeType="}.$params{body_mime}.q{"};
    }
	# Если в параметрах указана кодировка
    if (defined $params{body_encoding}) {
        $template .= q{ encoding="}.$params{body_encoding}.q{"};
    }
    $template .= qq{>};
    $template .= $params{body};
    $template .= q{</Body>};
    $template .= q{</Document>};
	# Путь к подписи
    my $sigpath = "/*[name()='Document']/*[name()='Header']/*[name()='SignatureContainer'][1]/*[name()='Signature']";

    my $r;
	# Подписать с параметрами
    eval {
        $r = xmldsig::sign({
            template => $template,
            sigpath  => $sigpath,
            cert     => $params{cert_file},
            key      => $params{pkey_file},
            pwd      => $params{pkey_pwd},
        });
    };
	# Если возникла ошибка
    if (my $err = $@) {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "Sign error"};
    }
	# Если результат содержит ошибку
    if ($r->{result} ne '0') {
		# Вернуть результат с ошибкой
        return {Result => 1, ErrCode => 10, ErrMsg => "xmldsig::sign error: ".$r->{errmsg}};
    }
	# Вернуть успешный результат
    return {Result => 0, ErrCode => 0, ErrMsg => '', Content => $r->{xml}, DocId => $doc_id};
}

# Метод создаёт таймстамп
sub _timestamp {
	# Форматировать строку с локальным временем
    my $dt = strftime("%Y-%m-%dT%T", localtime);
	# Форматировать строку с локальной таймзоной
    my $tz = strftime("%z", localtime);
	# Если таймзона имеет правильный формат
    if ($tz =~ /^([+-]\d\d)(\d\d)$/) {
		# Создать строку из двух частей таймзоны 
        $tz = $1 . ':' . $2;
    } else {
		# Создать строку с таймзоной по умолчанию
        $tz = '+00:00';
    }
	# Вернуть дату и таймзону
    return $dt.$tz;
}

# Метод получает значение xpath
sub _get_xpath_value {
	# Параматр узла
    my $node = shift;
	# Параметро пути
    my $xpath = shift;
	# Результат
    my $res = undef;
    eval {
		# Найти узлы по пути
        my $ns = $node->findnodes($xpath);
		# Если найдены
        if (scalar @$ns > 0) {
			# Присвоить результату текстовое значение первого узла
            $res = Encode::encode_utf8($ns->[0]->textContent());
        }
    };
	# Вернуть результат
    return $res;
}

# Метод загружает файл XSD
sub _load_xsd {
	# Параметр имени файла
    my $xsd_file_name = shift;
	# Получить том, папку и имя файла исполняемого скрипта
    my ($volume, $directory, $file) = File::Spec->splitpath(__FILE__);
	# Получить путь к папке XSD
    my $xsd_directory = File::Spec->join($directory, 'XSD');
	# Получить полный путь к файлу XSD
    my $xsd_file_path = File::Spec->catpath($volume, $xsd_directory, $xsd_file_name);
	# Получить контент из файла
    my $content = _load_file($xsd_file_path);
	# Вернуть контент
    return $content;
}
# Метод загружает файл
sub _load_file {
	# Параметр имени файла
    my $filename = shift;
	# Открыть файл
    open(my $rf, '<', $filename) or die "cannot open $filename: $!";
	# Прочитать данные
    my $data = do { local $/ = undef; <$rf> };
	# Закрыть файл
    close $rf;
	# Вернуть данные
    return $data;
}

1;