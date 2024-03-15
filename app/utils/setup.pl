#!/usr/bin/perl
use strict;
use utf8;
use warnings FATAL => 'all';

use Crypt::OpenSSL::X509;
use Data::Dumper;
use DBI;
use Digest::MD5 ();
use Encode;
use FindBin '$RealBin';
use Getopt::Long;
use YAML ();

use lib "$RealBin/../lib";

use CyberFT::Utils;

binmode STDOUT, ':utf8';

$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Terse = 1;

my $config_path;
my $dry_run = 0;
my $debug = 0;

GetOptions('config=s' => \$config_path, 'dry-run' => \$dry_run, 'debug' => \$debug);

my $config = load_config($config_path);

my $dbh = DBI->connect(
    $config->{db}{source},
    $config->{db}{username},
    $config->{db}{password} || ask_password("Please, enter the password for user $config->{db}{username}"),
    {
        RaiseError  => 1,
        AutoCommit  => 0,
        LongReadLen => 5242880,
    }
);
$dbh->do('set search_path to cyberft');
$dbh->do('set datestyle to "ISO, YMD"');

my ($old_processing_cert_body, $old_processing_cert_fingerprint) = load_certificate($config->{old_processing}{controller_cert}{file_path});

print "Deleting all existing members\n";
delete_all_members();

print "Deleting all existing routes\n";
delete_all_routes();

print "Creating old processing\n";
my $old_processing_id = create_processing({
    member_code  => $config->{old_processing}{code},
    swift_code   => $config->{old_processing}{swift_code},
    member_name  => $config->{old_processing}{name},
    registr_info => undef,
    lang_num     => 10,
    is_primary   => 0,
    eng_name     => undef,
    is_bank      => 0,
    cntr_code2   => undef,
    city_name    => undef,
    website      => undef,
    member_phone => undef,
    auto_modify  => 0,
});

activate_member($old_processing_id);

print "Creating old processing terminal\n";
my $old_processing_terminal_id = create_terminal({
    member_id      => $old_processing_id,
    terminal_code  => $config->{old_processing}{terminal}{code},
    terminal_name  => $config->{old_processing}{terminal}{name},
    work_mode      => 0,
    login_param    => Digest::MD5::md5_hex($config->{old_processing}{terminal}{local_broker_password}),
    login_addr     => $config->{old_processing}{terminal}{remote_broker_address} . ':' . $config->{old_processing}{terminal}{remote_broker_password},
    fragment_ready => 1,
    fragment_size  => undef,
    queue_length   => undef,
});

print "Creating old processing controller\n";
my $old_processing_operator_id = create_operator({
    member_id         => $old_processing_id,
    operator_name     => $config->{old_processing}{controller}{name},
    role_id           => 22,
    full_privs        => 1,
    terminal_id       => $old_processing_terminal_id,
    operator_position => undef,
    phone             => undef,
    email             => undef,
    external_code     => undef,
});

print "Creating old processing controller certificate\n";
my $key_code = $config->{old_processing}{code} . '-' . $old_processing_cert_fingerprint;
my $old_processing_key_id = create_key({
    owner_type  => 2,
    owner_id    => $old_processing_operator_id,
    key_type    => 2,
    crypto_type => 0,
    cert_center => 0,
    key_code    => $key_code,
    start_date  => $config->{old_processing}{controller_cert}{start_date},
    end_date    => $config->{old_processing}{controller_cert}{end_date},
    key_body    => $old_processing_cert_body,
});

print "Creating new processing\n";
my $new_processing_id = create_processing({
    member_code  => $config->{new_processing}{code},
    swift_code   => $config->{new_processing}{swift_code},
    member_name  => $config->{new_processing}{name},
    registr_info => undef,
    lang_num     => 10,
    is_primary   => 1,
    eng_name     => undef,
    is_bank      => 0,
    cntr_code2   => undef,
    city_name    => undef,
    website      => undef,
    member_phone => undef,
    auto_modify  => 0,
});

print "Creating new processing terminal\n";
my $new_processing_terminal_id = create_terminal({
    member_id      => $new_processing_id,
    terminal_code  => $config->{new_processing}{terminal}{code},
    terminal_name  => $config->{new_processing}{terminal}{name},
    work_mode      => 0,
    login_param    => Digest::MD5::md5_hex($config->{new_processing}{terminal}{local_broker_password}),
    login_addr     => undef,
    fragment_ready => 0,
    fragment_size  => undef,
    queue_length   => undef,
});

activate_member($new_processing_id);

print "Creating routing table record\n";
create_route($old_processing_id, $old_processing_id);

print "Setting up system params\n";
my $sys_params = $config->{system_params} || {};
$sys_params->{PARENT_PROCESSING} = $config->{old_processing}{code};
foreach my $param_key (keys %$sys_params) {
    print "Setting $param_key = $sys_params->{$param_key}\n";
    set_sys_param($param_key, $sys_params->{$param_key});
}

$dbh->commit unless $dry_run;

print "Done\n";

print 'Members: ' . Dumper(select_all('select * from v_members where status != 0'));
print 'Terminals: ' . Dumper(select_all('select * from v_terminals where status != 0'));
print 'Operators: ' . Dumper(select_all('select * from v_operators where status != 0'));
print 'Keys: ' . Dumper(select_all('select * from v_keys where status != 0'));
print 'System params: ' . Dumper(select_all('select * from v_sys_params'));

sub create_key {
    my ($params) = @_;

    my $result = execute_pg_function(
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
    my ($params) = @_;

    my $result = execute_pg_function(
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

sub create_route {
    my ($destination_id, $source_id) = @_;

    execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_member_api_add_route(:destination_id, :source_id)
        },
        {
            destination_id => $destination_id,
            source_id      => $source_id,
        }
    );
}

sub delete_all_routes {
    my $routes = select_all('select * from cyberft.v_routing_table');

    foreach my $route (@$routes) {
        execute_pg_function(
            q{
                select
                    piiserrorout as has_error,
                    pcerrcodeout as error_code,
                    pcerrmsgout as error_message
                from cyberft.p_member_api_del_route(:route_id)
            },
            {route_id => $route->{route_id}}
        );
    }
}

sub activate_member {
    my ($member_id) = @_;

    execute_pg_function(
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

sub set_sys_param {
    my ($key, $value) = @_;

    execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_param_api_edit(
                :key,
                :value
            )
        },
        {
            key   => $key,
            value => $value,
        }
    );
}

sub create_terminal {
    my ($params) = @_;

    my $result = execute_pg_function(
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

sub create_processing {
    my ($params) = @_;

    my $result = execute_pg_function(
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

sub delete_all_members {
    my $members = find_members();
    foreach my $m (@$members) {
        execute_pg_function(
            q{
                select
                    piiserrorout as has_error,
                    pcerrcodeout as error_code,
                    pcerrmsgout as error_message
                from cyberft.p_member_api_delete_member(:member_id, 1)
            },
            {member_id => $m->{member_id}}
        );
    }
}

sub find_member {
    my ($code) = @_;
    return select_one(
        'select * from cyberft.v_members where status != 0 and member_code = :code',
        {code => $code}
    );
}

sub find_members {
    return select_all(
        'select * from cyberft.v_members where status != 0 order by member_type desc',
    );
}

sub update_processing {
    my ($params) = @_;

    execute_pg_function(
        q{
            select
                piiserrorout as has_error,
                pcerrcodeout as error_code,
                pcerrmsgout as error_message
            from cyberft.p_member_api_update_processing(
                :member_id,
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
                :member_phone
            )
        },
        $params
    );
}

sub select_all {
    my ($query, $params) = @_;

    my $sth = $dbh->prepare($query);

    my $bound_params = {};
    if ($params) {
        foreach my $param_key (keys %$params) {
            next unless $query =~ m/[\s\(]\:\Q$param_key\E(?:$|[\s,\)])/;
            $sth->bind_param(":$param_key", $params->{$param_key});
            $bound_params->{$param_key} = $params->{$param_key};
        }
    }

    if ($debug) {
        print "Query: $query\nParams: " . Dumper($bound_params);
    }

    $sth->execute;

    my $results = [];
    while (my $row = $sth->fetchrow_hashref) {
        foreach my $key (keys %$row) {
            Encode::_utf8_off($row->{$key}) if utf8::is_utf8($row->{$key});
        }
        push @$results, $row;
    }

    return $results;
}

sub select_one {
    my ($query, $params) = @_;

    my $all = select_all($query, $params);

    return $all->[0];
}

sub execute_pg_function {
    my ($query, $params) = @_;

    my $result = select_one($query, $params);
    if ($result->{has_error}) {
        my ($function_name) = $query =~ /from\s+([a-z0-9_\.]+?)\(/i;
        die "Execution of $function_name failed, error: $result->{error_code}, $result->{error_message}";
    }

    return $result;
}

sub load_certificate {
    my ($file_path) = @_;
    CyberFT::Utils::read_file($file_path, \my $certificate_body);

    die "Failed to read certificate file $file_path"
        unless $certificate_body;

    my $x509 = Crypt::OpenSSL::X509->new_from_string($certificate_body);
    my $fingerprint = uc($x509->fingerprint_sha1());
    $fingerprint =~ s/://g;

    die 'Cannot get certificate fingerprint'
        unless $fingerprint;

    return ($certificate_body, $fingerprint);
}

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
