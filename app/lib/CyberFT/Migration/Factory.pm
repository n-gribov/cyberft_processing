package CyberFT::Migration::Factory;
use strict;
use utf8;
use warnings FATAL => 'all';

my $MIGRATION_CLASSES = {
    'member'           => 'CyberFT::Migration::MemberMigration',
    'all-members'      => 'CyberFT::Migration::AllMembersMigration',
    'document-systems' => 'CyberFT::Migration::DocumentSystemsMigration',
    'operator'         => 'CyberFT::Migration::OperatorMigration',
};

sub create {
    my ($migration_name, $dbh_ora, $dbh_pg, $dry_run) = @_;

    die __PACKAGE__ . "::create: migration name is required" unless $migration_name;

    my $class = $MIGRATION_CLASSES->{$migration_name};
    die __PACKAGE__ . "::create: cannot find class for $migration_name" unless $class;

    eval "require $class";
    die __PACKAGE__ . "::create: cannot load class $class: $@" if $@;

    my $instance = eval { $class->new($dbh_ora, $dbh_pg, $dry_run) };
    die __PACKAGE__ . "::create: cannot instantiate $class: $@" if $@;

    return $instance;
}

1;
