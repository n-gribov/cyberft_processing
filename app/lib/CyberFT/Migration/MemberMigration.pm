package CyberFT::Migration::MemberMigration;
use base 'CyberFT::Migration::BaseMigration';

use strict;
use utf8;
use warnings FATAL => 'all';

use Crypt::OpenSSL::X509;

my $MEMBER_TYPE_PROCESSING = 1;
my $KEY_OWNER_TYPE_OPERATOR = 2;

sub execute {
    my ($self, $member_swift_code) = @_;

    my $ora_member = $self->find_member_by_swift_code($self->dbh_ora, $member_swift_code);
    die "Member $member_swift_code is not found" unless $ora_member;

    my $pg_member = $self->find_member_by_swift_code($self->dbh_pg, $member_swift_code);
    if ($pg_member) {
        print "Deleting existing member\n";
        $self->delete_member($pg_member->{member_id});
    }

    my $pg_member_id = $ora_member->{member_type} == $MEMBER_TYPE_PROCESSING
        ? $self->create_processing($ora_member)
        : $self->migrate_member($ora_member);

    $pg_member = $self->find_member_by_swift_code($self->dbh_pg, $member_swift_code);

    if ($ora_member->{status} == 1 && $pg_member->{status} == 2) {
        $self->activate_member($pg_member_id);
    }

    print "Done.\n";
}

sub delete_member {
    my ($self, $member_id) = @_;

    $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_member_api_delete_member(:member_id, 1)
        },
        {member_id => $member_id}
    );
}

sub activate_member {
    my ($self, $member_id) = @_;

    $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_member_api_activate_member(:member_id)
        },
        {member_id => $member_id}
    );
}

sub migrate_member {
    my ($self, $ora_member) = @_;

    print "Migrating member $ora_member->{member_code}\n";

    my $pg_member_id = $self->create_member($ora_member);

    my $ora_terminals = $self->find_terminals($ora_member->{member_id});
    foreach my $ora_terminal (@$ora_terminals) {
        $self->migrate_terminal($ora_terminal, $pg_member_id);
    }

    return $pg_member_id;
}

sub migrate_terminal {
    my ($self, $ora_terminal, $pg_member_id) = @_;

    print "Migrating terminal $ora_terminal->{full_swift_code}\n";

    my $pg_terminal_id = $self->create_terminal({
        %$ora_terminal,
        (member_id => $pg_member_id)
    });

    my $ora_operators = $self->find_operators($ora_terminal->{terminal_id});
    foreach my $ora_operator (@$ora_operators) {
        $self->migrate_operator($ora_operator, $pg_member_id, $pg_terminal_id);
    }
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

    if ($params->{status} == 1) {
        $self->activate_key($result->{key_id});
    }

    return $result->{key_id};
}

sub activate_key {
    my ($self, $key_id) = @_;

    $self->execute_pg_function(
        q{
            select
                piIsErrorOut as has_error,
                pcErrCodeOut as error_code,
                pcErrMsgOut as error_message
            from cyberft.p_member_api_activate_key(:key_id)
        },
        {key_id => $key_id}
    );
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
        'select * from edo3.w_keys where owner_id = :operator_id and owner_type = 2 and status in (1, 3)',
        {operator_id => $operator_id}
    );
}

sub find_operators {
    my ($self, $terminal_id) = @_;

    return $self->select_all(
        $self->dbh_ora,
        'select * from edo3.w_operators where terminal_id = :terminal_id and status = 1 and (blocked = 0 or blocked is null)',
        {terminal_id => $terminal_id}
    );
}

sub create_terminal {
    my ($self, $params) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                piterminalout as terminal_id
            from cyberft.p_member_api_create_terminal(
                :member_id,
                :terminal_code,
                :terminal_name,
                :work_mode,
                :login_param,
                :login_addr,
                :fragment_ready,
                :fragment_size,
                :queue_length
            )
        },
        $params
    );

    return $result->{terminal_id};
}

sub find_terminals {
    my ($self, $member_id) = @_;

    return $self->select_all(
        $self->dbh_ora,
        'select * from edo3.w_terminals where member_id = :member_id and status = 1 and (blocked = 0 or blocked is null)',
        {member_id => $member_id}
    );
}

sub create_member {
    my ($self, $params) = @_;

    my $parent_processing = $self->find_member_by_swift_code($self->dbh_pg, $params->{proc_swift_code});
    die "Processing $params->{proc_swift_code} is not found"
        unless $parent_processing && $parent_processing->{member_type} == $MEMBER_TYPE_PROCESSING;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pimemberout as member_id
            from cyberft.p_member_api_create_member(
                :member_code,
                :swift_code,
                :member_name,
                :registr_info,
                :lang_num,
                :parent,
                :eng_name,
                :is_bank,
                :cntr_code2,
                :city_name,
                :website,
                :member_phone,
                :auto_modify
            )
        },
        {
            %$params,
            (parent => $parent_processing->{member_id})
        }
    );

    return $result->{member_id};
}

sub create_processing {
    my ($self, $params) = @_;

    my $result = $self->execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message,
                pimemberout as member_id
            from cyberft.p_member_api_create_processing(
                :member_code,
                :swift_code,
                :member_name,
                :registr_info,
                :lang_num,
                :is_primary,
                :eng_name,
                :is_bank,
                :cntr_code2,
                :city_name,
                :website,
                :member_phone,
                :auto_modify
            )
        },
        $params
    );

    return $result->{member_id};
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
