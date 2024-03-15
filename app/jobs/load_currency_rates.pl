#!/usr/bin/perl
use strict;
use DBI;
use Date::Calc ();
use FindBin;
use Getopt::Long;
use Sys::Syslog;

use lib $FindBin::RealBin . '/../lib';

use CyberFT::Database;
use CyberFT::Utils;

my $log;
my $CURRENCIES = {
    USD => 20645,
    EUR => 3915820,
};

eval {
    main();
};
if (my $err = $@) {
    _log("error", "Error in main(): $err");
}

sub main {
    # Прочитаем конфигурационный файл.
    my $cfg = CyberFT::Utils::read_app_config();
    unless (defined $cfg) {
        die "Error reading config file (config/cyberft.cfg)";
    }

    openlog($cfg->{log_ident}, "ndelay,pid", $cfg->{log_facility});
    $log = CyberFT::Utils::log_func_syslog("load_currency_rates");

    _log("info", "Start");

    # Подключимся к базе данных
    my $db = CyberFT::Database::new_instance($cfg);
    my $res = $db->connect();
    if ($res->{Result} ne '0') {
        die('Database connection error: ' . $res->{ErrMsg});
    }
    my $cyberplat_dbh = get_cyberplat_dbh($cfg);

    my $date = get_date();

    foreach my $currency_code (keys %$CURRENCIES) {
        _log('info', "Copying rate for $currency_code, $date");
        my $id = $CURRENCIES->{$currency_code};
        eval {
            my $rate = get_rate($cyberplat_dbh, $id, $date);
            if ($rate) {
                my $result = $db->save_currency_rate({
                    CurrCode => $currency_code,
                    Rate     => $rate,
                    RateDate => $date,
                });
                if ($result->{Result} ne '0') {
                    _log("error", "Failed to copy rate: " . $result->{ErrCode} . ', ' . $result->{ErrMsg});
                }
            }
        };
        if (my $exception = $@) {
            _log('warning', "Failed to copy rate, caused by: $exception");
        }
    }

    _log("info", "Stop");
    return 1;
}

sub get_rate {
    my ($dbh, $id, $date) = @_;

    my $sth = $dbh->prepare(q{
        select inist.lpcurr.l_getCurrRate(:id, 100, to_date(:rate_date, 'YYYY-MM-DD')) as "rate"
        from dual
    });
    $sth->bind_param(':id', $id);
    $sth->bind_param(':rate_date', $date);
    $sth->execute();
    if (my $row = $sth->fetchrow_hashref) {
        return $row->{rate};
    }
    return undef;
}

sub get_cyberplat_dbh{
    my ($config) = @_;
    return DBI->connect(
        $config->{db_cyberplat_data_source},
        $config->{db_cyberplat_username},
        $config->{db_cyberplat_password},
        {
            RaiseError       => 1,
            PrintError       => 1,
            AutoCommit       => 1,
            LongTruncOk      => 0,
            FetchHashKeyName => 'NAME_lc',
        }
    );
}

sub get_date {
    my $date =  '';
    GetOptions('date=s' => \$date);
    if ($date) {
        if ($date !~ m/^\d{4}-\d{2}-\d{2}$/) {
            die 'Date must be in YYYY-DD-MM format';
        }
        return $date;
    }
    return get_default_date();
}

sub get_default_date {
    my @today = Date::Calc::Today;
    my @tomorrow = Date::Calc::Add_Delta_YMD(@today, 0, 0, 1);
    return(sprintf("%04d-%02d-%02d", @tomorrow));
}

sub _log{
    my $type = shift;
    my $msg = shift;
    if (defined $log) {
        $log->($type, $msg);
    } else {
        print STDERR "load_currency_rates: <$type> $msg\n";
    }
}
