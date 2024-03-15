package CyberFT::CFTMQUsersSyncUtils;

use strict;
use utf8;
use warnings;

use JSON::XS;

use CyberFT::Utils;

sub save_users_sync_status {
    my ($params) = @_;
    my ($config, $last_update_timestamp, $force_update) = map { $params->{$_} } qw(config last_update_timestamp force_update);

    my $user_sync_status_file_path = get_users_sync_status_file_path($config);
    my $user_sync_status = get_users_sync_status($config);
    $user_sync_status->{last_update_timestamp} = $last_update_timestamp
        if $last_update_timestamp;
    $user_sync_status->{force_update} = $force_update;

    my $user_sync_status_json = JSON::XS->new->encode($user_sync_status);
    CyberFT::Utils::write_file($user_sync_status_file_path, \$user_sync_status_json);

    system("chmod a+rw $user_sync_status_file_path");
}

sub get_users_sync_status {
    my ($config) = @_;
    my $user_sync_status_file_path = get_users_sync_status_file_path($config);

    my $default_data = { last_update_timestamp => undef, force_update => 0 };
    return $default_data
        unless -e $user_sync_status_file_path;

    my $data = eval {
        CyberFT::Utils::read_file($user_sync_status_file_path, \my $user_sync_status_json);
        return JSON::XS->new->decode($user_sync_status_json);
    };
    if (my $exception = $@) {
        print STDERR __PACKAGE__ . "::get_users_sync_status: failed to read status data from $user_sync_status_file_path, caused by: $exception";
        return $default_data;
    }
    return $data;
}

sub get_users_sync_status_file_path {
    my ($config) = @_;
    return "$config->{temp_dir}/users_sync_status.json";
}

1;
