package CyberFT::Migration::OperatorMigration;
use base 'CyberFT::Migration::BaseMigration';

use strict;
use utf8;
use warnings FATAL => 'all';

use Crypt::OpenSSL::X509;

my $KEY_OWNER_TYPE_OPERATOR = 2;

sub execute {
    my ($self, $operator_id) = @_;

    my $ora_operator = $self->find_operator($operator_id);
    die "Operator is not found" unless $ora_operator;

    my $pg_member = $self->find_member_by_swift_code($self->dbh_pg, $ora_operator->{swift_code});
    die "Member $ora_operator->{swift_code} is not found in new database" unless $pg_member;

    my $pg_terminal = $self->find_terminal_by_swift_code($self->dbh_pg, $ora_operator->{full_swift_code});
    die "Terminal $ora_operator->{full_swift_code} is not found in new database" unless $pg_terminal;

    $self->migrate_operator($ora_operator, $pg_member->{member_id}, $pg_terminal->{terminal_id});

    print "Done.\n";
}

sub migrate_operator {
    my ($self, $ora_operator, $pg_member_id, $pg_terminal_id) = @_;

    print "Migrating operator $ora_operator->{operator_name}, $ora_operator->{role_name}\n";

    my $pg_operator_id = $self->create_operator({
        %$ora_operator,
        (
            member_id   => $pg_member_id,
            terminal_id => $pg_terminal_id,
        )
    });

    my $ora_keys = $self->find_keys($ora_operator->{operator_id});
    foreach my $ora_key (@$ora_keys) {
        $self->migrate_operator_key($ora_key, $pg_operator_id);
    }
}

sub migrate_operator_key {
    my ($self, $ora_key, $pg_operator_id) = @_;

    print "Migrating key $ora_key->{key_code}\n";

    my $key_body = $ora_key->{key_body};
    if (index($key_body, 'BEGIN CERTIFICATE') == -1) {
        print "Key body is probably in ASN1 format, trying to convert to PEM...\n";
        eval {
            my $x509 = Crypt::OpenSSL::X509->new_from_string($key_body, Crypt::OpenSSL::X509::FORMAT_ASN1);
            $key_body = $x509->as_string(Crypt::OpenSSL::X509::FORMAT_PEM);
        };
        if (my $exception = $@) {
            print "Failed to convert key body, caused by: $exception\n";
            print "Key $ora_key->{key_code} was not migrated\n";
        }
    }

    $self->create_key({
        %$ora_key,
        (
            owner_type => $KEY_OWNER_TYPE_OPERATOR,
            owner_id   => $pg_operator_id,
            key_body   => $key_body,
        )
    });
}

sub create_key {
    my ($self, $params) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pikeyout as key_id
            from cyberft.p_member_api_add_key(
                :owner_type,
                :owner_id,
                :key_type,
                :crypto_type,
                :cert_center,
                :key_code,
                :start_date,
                :end_date,
                :key_body
            )
        },
        $params
    );

    return $result->{key_id};
}

sub create_operator {
    my ($self, $params) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pioperatorout as operator_id
            from cyberft.p_member_api_create_operator(
                :member_id,
                :operator_name,
                :role_id,
                :full_privs,
                :terminal_id,
                :operator_position,
                :phone,
                :email,
                :external_code
            )
        },
        $params
    );

    return $result->{operator_id};
}

sub find_keys {
    my ($self, $operator_id) = @_;

    return $self->select_all(
        $self->dbh_ora,
        'select * from edo3.w_keys where owner_id = :operator_id and owner_type = 2 and status = 1',
        {operator_id => $operator_id}
    );
}

sub find_operator {
    my ($self, $id) = @_;

    return $self->select_one(
        $self->dbh_ora,
        'select * from edo3.w_operators where operator_id = :operator_id and status = 1 and (blocked = 0 or blocked is null)',
        {operator_id => $id}
    );
}

sub find_terminal_by_swift_code {
    my ($self, $dbh, $code) = @_;

    return $self->select_one(
        $dbh,
        'select * from v_terminals where full_swift_code = :code and status = 1 and (blocked = 0 or blocked is null)',
        {code => $code}
    );
}

sub find_member_by_swift_code {
    my ($self, $dbh, $code) = @_;

    return $self->select_one(
        $dbh,
        q{select * from v_members where swift_code = :code and status != 0},
        {code => $code}
    );
}

1;
