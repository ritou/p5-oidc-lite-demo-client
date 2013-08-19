use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Session;
use Plack::Session;

my $session = Plack::Session->new({
   'psgix.session' => +{},    
   'psgix.session.options' => +{},    
});
my $provider = 'Google';
my $state = OIDC::Lite::Demo::Client::Session->generate_state($session, $provider);
ok($state);

my $state2 = OIDC::Lite::Demo::Client::Session->generate_state($session, $provider);
ok(($state ne $state2), q{state is not saved and re-generated});

OIDC::Lite::Demo::Client::Session->set_state($session, $provider, $state);
$state2 = OIDC::Lite::Demo::Client::Session->get_state($session, $provider);
is($state, $state2, q{state is saved and loaded});

$state2 = OIDC::Lite::Demo::Client::Session->generate_state($session, $provider);
is($state, $state2, q{state is note re-generated});

done_testing;
