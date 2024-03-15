package CyberFT::Migration::DocumentSystemsMigration;
use base 'CyberFT::Migration::BaseMigration';

use strict;
use utf8;
use warnings FATAL => 'all';

sub execute {
    my ($self) = @_;

    print "Deleting existing systems\n";
    $self->delete_all_doc_systems;

    my $ora_doc_systems = $self->find_doc_systems($self->dbh_ora);
    foreach my $ora_doc_system (@$ora_doc_systems) {
        $self->migrate_doc_system($ora_doc_system);
    }

    print "Done.\n";
}

sub migrate_doc_system {
    my ($self, $ora_doc_system) = @_;

    print "Migrating document system $ora_doc_system->{system_name}\n";

    my $pg_doc_system_id = $self->create_doc_system($ora_doc_system->{system_name});

    my $ora_doc_groups = $self->find_doc_groups($self->dbh_ora, $ora_doc_system->{system_id});
    foreach my $ora_doc_group (@$ora_doc_groups) {
        $self->migrate_doc_group($ora_doc_group, $pg_doc_system_id);
    }
}

sub migrate_doc_group {
    my ($self, $ora_doc_group, $pg_doc_system_id) = @_;

    my $name = $ora_doc_group->{group_name} // '(no name)';
    print "Migrating document group $name\n";

    my $pg_doc_group_id = $self->create_doc_group($ora_doc_group, $pg_doc_system_id);

    my $ora_message_types = $self->find_message_types($self->dbh_ora, $ora_doc_group->{group_id});
    foreach my $ora_message_type (@$ora_message_types) {
        $self->migrate_message_type($ora_message_type, $pg_doc_group_id);
    }
}

sub migrate_message_type {
    my ($self, $ora_message_type, $pg_doc_group_id) = @_;

    print "Migrating message type $ora_message_type->{message_code}\n";

    $self->create_message_type({
        %$ora_message_type,
        (group_id => $pg_doc_group_id),
        (is_register => 0),
    });
}

sub create_message_type {
    my ($self, $params) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pimessagetypeout as type_id
            from cyberft.p_message_api_create_message_type(
                :message_code,
                :message_name,
                :info,
                :need_permission,
                :broadcast,
                :is_register,
                :group_id,
                :system_message
            )
        },
        $params
    );

    return $result->{type_id};
}

sub create_doc_group {
    my ($self, $ora_doc_group, $pg_doc_system_id) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pigroupout as group_id
            from cyberft.p_doc_group_api_add(:name, :system_id)
        },
        {
            name      => $ora_doc_group->{group_name},
            system_id => $pg_doc_system_id,
        }
    );

    return $result->{group_id};
}

sub create_doc_system {
    my ($self, $system_name) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pisystemout as system_id
            from cyberft.p_doc_system_api_add(:system_name)
        },
        {system_name => $system_name}
    );

    return $result->{system_id};
}

sub delete_all_doc_systems {
    my ($self) = @_;

    my $doc_systems = $self->find_doc_systems($self->dbh_pg);
    foreach my $doc_system (@$doc_systems) {
        $self->delete_doc_system($doc_system->{system_id});
    }
}

sub delete_doc_system {
    my ($self, $system_id) = @_;

    $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_doc_system_api_del(:system_id, 1)
        },
        {system_id => $system_id}
    );
}

sub find_doc_systems {
    my ($self, $dbh) = @_;

    return $self->select_all(
        $dbh,
        q{select * from v_doc_systems where status = 1}
    );
}

sub find_doc_groups {
    my ($self, $dbh, $system_id) = @_;

    return $self->select_all(
        $dbh,
        q{select * from v_doc_groups where status = 1 and system_id = :system_id},
        {system_id => $system_id}
    );
}

sub find_message_types {
    my ($self, $dbh, $group_id) = @_;

    return $self->select_all(
        $dbh,
        q{select * from v_message_types where status = 1 and group_id = :group_id},
        {group_id => $group_id}
    );
}

1;
