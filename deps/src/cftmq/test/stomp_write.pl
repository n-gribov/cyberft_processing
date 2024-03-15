use Net::Stomp;
my $stomp = Net::Stomp->new( { hostname => '192.168.6.36', port => '40090' } );
$stomp->connect( { login => 'root', passcode => '' } );

foreach my $i (0..1000)
{
	$stomp->send(
    	{ destination => 'test', receipt => $i, body => 'test message ' . $i  } );

	my $frame = $stomp->receive_frame;
	if (defined $frame)
	{
		printf("%s\n",$i);
	}

}

$stomp->disconnect;
