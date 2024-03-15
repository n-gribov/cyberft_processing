# subscribe to messages from the queue 'foo'
use Net::Stomp;
my $stomp = Net::Stomp->new( { hostname => '192.168.6.36', port => '40090' } );
$stomp->connect( { login => 'root', passcode => '' } );
$stomp->subscribe(
    {   destination             => 'test',
        'ack'                   => 'client'
    }
);
while (1) {
  my $frame = $stomp->receive_frame;
  if (!defined $frame) {
    # maybe log connection problems
    next; # will reconnect automatically
  }
  printf("%s\n",$frame->body);

  $stomp->ack( { frame => $frame } );
}
$stomp->disconnect;