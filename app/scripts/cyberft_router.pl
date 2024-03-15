#!/usr/bin/perl
use strict;
use utf8;
use Data::Dumper;
use FindBin;
use Sys::Syslog;
use Getopt::Long;
use POSIX qw(strftime);

use lib $FindBin::RealBin . '/../lib';
use CyberFT::Router;
use CyberFT::Utils;

my $procid;
GetOptions('procid=i' => \$procid);

# Имя в списке процессов
$0 = "cyberft_router #$procid";

# Прочитаем конфигурационный файл.
my $cfg = CyberFT::Utils::read_app_config();
unless (defined $cfg) {
    die "Error reading config file (config/cyberft.cfg)";
}

# Проверим настройки логирования.
unless (defined $cfg->{log_ident} && defined $cfg->{log_facility}) {
    die "Error reading log settings (log_ident, log_facility)";
}
openlog($cfg->{log_ident}, "ndelay,pid", $cfg->{log_facility});

# CyberFT::Router не пишет напрямую лог, а вызывает ф-ю log_func.
my $log = CyberFT::Utils::log_func_syslog("router", $procid);
$log->("info", "Worker ~ start");

# Флаг для остановки главного цикла
my $done = 0;

# Обработка сигнала остановки.
$SIG{TERM} = sub {
    $log->('info', 'TERM signal received');
    $done = 1;
};

# Создаем и инициализируем роутер.
my $router = CyberFT::Router->new;
my $r = $router->init(%$cfg, log_func => $log);
if ($r->{Result} ne '0') {
    $log->("error", "Router init failed: " . $r->{ErrMsg});
    exit;
}

# Запуск основного цикла обработки сообщений
$router->process_loop(\$done);
$router->cleanup();
$log->("info", "Worker ~ stop");
