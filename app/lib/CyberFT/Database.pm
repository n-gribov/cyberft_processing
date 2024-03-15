# Класс для работы с базой данных

package CyberFT::Database;

use strict;
use utf8;

sub new_instance {
    my ($config) = @_;

    my ($driver) = ($config->{db_data_source} =~ m/^dbi\:([a-z]+)\:.*$/i);
    die __PACKAGE__ .  "new_instance: cannot find driver name data source: $config->{db_data_source}"
        unless defined($driver) && $driver;

    my $class = undef;
    if ($driver eq 'Pg') {
        $class = 'CyberFT::Database::PostgresDatabase';
    } elsif ($driver eq 'Oracle') {
        $class = 'CyberFT::Database::OracleDatabase';
    } else {
        die __PACKAGE__ .  "new_instance: unsupported driver: $driver";
    }

    eval "require $class";
    die __PACKAGE__ . "::new_instance: cannot load class $class: $@"
        if $@;

    my $instance = eval { $class->new($config) };
    die __PACKAGE__ . "::create: cannot instantiate $class: $@"
        if $@;

    return $instance;
}

sub new {
    my $class = shift;
    my $config = shift;
    my $self = {config => $config};
    bless $self, $class;
}

sub config {
    my ($self) = @_;
    return $self->{config};
}

1;
