package OIDC::Lite::Demo::Client::Session;

use strict;
use warnings;
use utf8;
use Crypt::OpenSSL::Random qw/random_pseudo_bytes/;

sub generate_state {
    my ($self, $session, $provider) = @_;
    return $self->get_state($session, $provider) || 
        unpack('H*', $provider.random_pseudo_bytes(32));
}

sub get_state {
    my ($self, $session, $provider) = @_;
    return $session->get('state_'.$provider) || '';
}

sub set_state {
    my ($self, $session, $provider, $state) = @_;
    $session->set('state_'.$provider, $state);
}

sub get_server_state {
    my ($self, $session, $provider) = @_;
    return $session->get('server_state_'.$provider) || '';
}

sub set_server_state {
    my ($self, $session, $provider, $state) = @_;
    $session->set('server_state_'.$provider, $state);
}

1;
