#!/usr/bin/perl
use strict;
use utf8;
use warnings FATAL => 'all';

use DBI;
use FindBin '$RealBin';
use Getopt::Long;
use YAML ();

use lib "$RealBin/../lib";

use CyberFT::Migration::Factory;

binmode STDOUT, ':utf8';

my $config_path;
my $dry_run = 0;

GetOptions('config=s' => \$config_path, 'dry-run' => \$dry_run);

my $config = load_config($config_path);

$ENV{NLS_LANG} = "AMERICAN_AMERICA.AL32UTF8";

my $ora_password = $config->{db_oracle}{password}
    || ask_password("Please, enter $config->{db_oracle}{username}'s password for $config->{db_oracle}{source}");
my $dbh_ora = DBI->connect(
    $config->{db_oracle}{source},
    $config->{db_oracle}{username},
    $ora_password,
    {
        RaiseError       => 1,
        FetchHashKeyName => 'NAME_lc',
        LongReadLen      => 5242880,
    }
);
$dbh_ora->do('alter session set current_schema = edo3');
$dbh_ora->do("alter session set nls_date_format = 'yyyy-mm-dd hh24:mi:ss'");

my $pg_password = $config->{db_postgres}{password}
    || ask_password("Please, enter $config->{db_postgres}{username}'s password for $config->{db_postgres}{source}");
my $dbh_pg = DBI->connect(
    $config->{db_postgres}{source},
    $config->{db_postgres}{username},
    $pg_password,
    {
        RaiseError  => 1,
        AutoCommit  => 0,
        LongReadLen => 5242880,
    }
);
$dbh_pg->do('set search_path to cyberft');
$dbh_pg->do('set datestyle to "ISO, YMD"');

my $migration_name = $ARGV[0];
my @migration_params = @ARGV[1 .. @ARGV - 1];

my $migration = CyberFT::Migration::Factory::create($migration_name, $dbh_ora, $dbh_pg, $dry_run);
$migration->run(@migration_params);

sub load_config {
    my ($file_path) = @_;

    die "Config file $file_path is not found"
        unless -f $file_path;

    return YAML::LoadFile($config_path);
}

sub ask_password {
    my ($prompt) = @_;
    print "$prompt: ";
    system('stty','-echo');
    chop(my $password = <STDIN>);
    system('stty','echo');
    print "\n";
    return $password;
}