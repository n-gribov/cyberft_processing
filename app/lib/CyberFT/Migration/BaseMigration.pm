package CyberFT::Migration::BaseMigration;
use strict;
use warnings FATAL => 'all';
use utf8;

sub new {
    my ($class, $dbh_ora, $dbh_pg, $dry_run) = @_;
    my $self = {
        dbh_ora => $dbh_ora,
        dbh_pg  => $dbh_pg,
        dry_run => $dry_run || 0,
    };

    return bless $self, $class;
}

sub run {
    my $self = shift;
    $self->execute(@_);
    $self->dbh_pg->commit unless $self->is_dry_run;
}

sub execute {
    my ($self) = @_;
    die "CyberFT::Migration::BaseMigration::execute must be overridden in subclass";
}

sub select_all {
    my ($self, $dbh, $query, $params) = @_;

    my $sth = $dbh->prepare($query);
    if ($params) {
        foreach my $param_key (keys %$params) {
            next unless $query =~ m/[\s\(]\:\Q$param_key\E(?:$|[\s,\)])/;
            $sth->bind_param(":$param_key", $params->{$param_key});
        }
    }
    $sth->execute;

    my $results = [];
    while (my $row = $sth->fetchrow_hashref) {
        push @$results, $row;
    }

    return $results;
}

sub select_one {
    my ($self, $dbh, $query, $params) = @_;

    my $all = $self->select_all($dbh, $query, $params);

    return $all->[0];
}

sub execute_pg_function {
    my ($self, $query, $params) = @_;

    my $result = $self->select_one($self->dbh_pg, $query, $params);
    if ($result->{has_error}) {
        my ($function_name) = $query =~ /from\s+([a-z0-9_\.]+?)\(/i;
        die "Execution of $function_name failed, error: $result->{error_code}, $result->{error_message}";
    }

    return $result;
}

sub dbh_ora {
    my ($self) = @_;
    return $self->{dbh_ora};
}

sub dbh_pg {
    my ($self) = @_;
    return $self->{dbh_pg};
}

sub is_dry_run {
    my ($self) = @_;
    return $self->{dry_run};
}

1;
