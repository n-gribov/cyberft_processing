package CyberFT::Utils;

use strict;
use utf8;
use Data::Dumper;
use Digest::MD5 ();
use Sys::Syslog;
use Time::HiRes ();
use POSIX qw(strftime);
use Exporter 'import';
use File::Basename;

our @EXPORT_OK = qw(
    read_config
    escape_crlf
    remove_crlf
    read_file
    write_file
    dumper
    md5_sum_file
    temp_filename
    log_func_syslog
    write_pid
    check_pid
    timestamp_hires
    gen_timestamps
);

sub read_app_config {
    my $dir = dirname(__FILE__);
    return read_config("$dir/../../../config/cyberft.cfg");
}

sub read_config {
    my $filename = shift;
    my $cfg = {};

    open(my $f, '<', $filename) or return undef;
    while (my $line = readline($f)) {
        $line =~ s/\s*#.*//;
        if ($line =~ /\s*(\w+)\s*=\s*(.*)/) {
            my $key = $1;
            my $value = $2;
            $value =~ s/^\s*|\s*$//g;
            if ($value =~ /^(["'])(.*)\1$/) { # "for syntax highlight fix
                $value = $2;
            }
            $cfg->{$key} = $value;
        }
    }
    close($f);

    return $cfg;
}

sub escape_crlf {
    my $str = shift;
    $str =~ s/\n/\\n/g;
    $str =~ s/\r/\\r/g;
    return $str;
}

sub remove_crlf {
    my $str = shift;
    $str =~ s/[\r\n]+/ /g;
    return $str;
}

sub read_file {
    my $filename = shift;
    my $data_ref = shift;
    open(my $f, '<', $filename) || die "read_file: cannon open $filename, caused by: $!";
    binmode $f;
    my $pos = 0;
    my $size = -s $filename;
    return unless ($size && $size > 0);
    while ($pos < $size) {
        my $n = read($f, $$data_ref, $size - $pos, $pos);
        die "read_file: cannon read $filename, caused by: $!" unless (defined $n);
        last if ($n <= 0);
        $pos += $n;
    }
}

sub write_file {
    my $filename = shift;
    my $data_ref = shift;
    open(my $f, '>', $filename) || die "write_file: cannot open $filename, caused by: $!";
    binmode $f;
    print $f $$data_ref;
    close($f);
}

sub dumper {
    my $val = shift;
    {
        local $Data::Dumper::Indent = 0;
        my $res = Dumper($val);
        $res =~ s/^\$VAR1 = //;
        return $res;
    }
}

sub md5_sum_file {
    my $file_name = shift;
    open(my $input, "<", $file_name) or die "md5_sum_file: $!";
    my $ctx = Digest::MD5->new;
    $ctx->addfile($input);
    my $digest = $ctx->hexdigest;
    close($input);
    return $digest;
}

sub temp_filename {
    my ($dir, $prefix) = @_;
    $dir =~ s|/$||;
    my ($time, $micro) = Time::HiRes::gettimeofday();
    my $tm = sprintf('%s%06d', strftime("%Y%m%d%H%M%S", localtime($time)), $micro);
    my $rnd = join(undef, map { ("a" .. "z", 0 .. 9)[rand 36] } 1..16);
    my $fn = $dir . '/' . $prefix . '_' . $tm . '_' . $rnd . '.tmp';
    return $fn;
}

my $_log_level_to_syslog = {
    err     => 'err',
    error   => 'err',
    warn    => 'warning',
    warning => 'warning',
    info    => 'info',
    debug   => 'debug',
};

my $_log_level_to_tag = {
    err     => 'E',
    error   => 'E',
    warn    => 'W',
    warning => 'W',
    info    => 'I',
    debug   => 'D',
};

sub log_func_syslog {
    my ($service, $tid) = @_;
    return sub {
        my $type = shift;
        my $msg = shift;
        my $level = $_log_level_to_syslog->{$type} || 'info';
        my $tag = $_log_level_to_tag->{$type} || 'I';
        if (defined $tid) {
            syslog($level, "%s [%d] [%s] %s", $service, $tid, $tag, $msg);
        } else {
            syslog($level, "%s [%s] %s", $service, $tag, $msg);
        }
    };
}

sub write_pid {
    my ($pid_file, $pid) = @_;
    unless (defined $pid) {
        $pid = $$;
    }
    write_file($pid_file, \$pid);
}

sub check_pid {
    my ($pid_file, $scan_name) = @_;
    return 0 unless (-f $pid_file);
    read_file($pid_file, \my $pid);
    return 0 unless ($pid =~ /^\d+$/ && $pid > 0);
    return 0 unless (kill 0, $pid);
    if ($scan_name) {
        open(my $f, "-|", "ps", "-p", $pid, "-o", "cmd=") or die "check_pid: $!";
        while (my $line = <$f>) {
            return 1 if ($line =~ $scan_name);
        }
        return 0;
    }
    return 1;
}

sub gen_timestamps {
    my @lt = localtime();
    my $dt = strftime("%Y-%m-%dT%T", @lt);
    my $tz = strftime("%z", @lt);
    if ($tz =~ /^([+-]\d\d)(\d\d)$/) {
        $tz = $1 . ':' . $2;
    } else {
        $tz = '+00:00';
    }
    my $xml_timestamp = $dt.$tz;
    my $db_timestamp = strftime("%Y-%m-%d %T", @lt);
    return ($xml_timestamp, $db_timestamp);
}

sub timestamp_hires {
    my ($time, $micro) = Time::HiRes::gettimeofday();
    return sprintf('%s.%06d', strftime("%Y-%m-%dT%T", localtime($time)), $micro);
}

1;