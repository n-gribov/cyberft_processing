package CyberFT::Migration::AllMembersMigration;
use base 'CyberFT::Migration::BaseMigration';

use strict;
use utf8;
use warnings FATAL => 'all';

use Crypt::OpenSSL::X509;

use CyberFT::Migration::MemberMigration;

sub execute {
    my ($self) = @_;

    my $member_migration = new CyberFT::Migration::MemberMigration($self->dbh_ora, $self->dbh_pg, $self->is_dry_run);
    my $all_members = $self->find_all_members();
    foreach my $ora_member (@$all_members) {
        print "Will copy $ora_member->{swift_code}\n";
        $member_migration->execute($ora_member->{swift_code});
    }

    print "Done.\n";
}

sub find_all_members {
    my ($self) = @_;
    return $self->select_all(
        $self->dbh_ora,
        'select * from edo3.v_members where status != 0 order by member_type'
    );
}

1;
