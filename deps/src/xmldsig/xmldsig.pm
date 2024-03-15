package xmldsig;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw(
	sign
    verify
    encrypt
    decrypt
);
$VERSION = '0.01';


bootstrap xmldsig $VERSION;
1;
__END__
