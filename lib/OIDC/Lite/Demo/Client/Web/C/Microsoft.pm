package OIDC::Lite::Demo::Client::Web::C::Microsoft;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OIDC::Lite::Client::WebServer;
use OIDC::Lite::Model::IDToken;
use JSON qw/encode_json decode_json/;

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/microsoft/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{Microsoft});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{Microsoft}, $state);

    # build authorize request URL
    my $config = $c->config->{'Credentials'}->{'Microsoft'};
    my $uri = $self->_uri_to_authorizatin_endpoint( $config, $state );

    my $req = $c->req;
    if ( $req->param('mode') && $req->param('mode') eq q{id_token}) {
        $uri=~ s/response_type=code/response_type=id_token/g;
    }
    return $c->redirect($uri);
}

sub _uri_to_authorizatin_endpoint {
    my ($self, $config, $state) = @_;

    return $self->_client( $config )->uri_to_redirect(
        redirect_uri    => $config->{'redirect_uri'},
        scope           => $config->{'scope'},
        state           => $state,
    );
}

sub _client {
    my ($self, $config) = @_;

    return OIDC::Lite::Client::WebServer->new(
        id               => $config->{'client_id'},
        secret           => $config->{'client_secret'},
        authorize_uri    => $config->{'authorization_endpoint'},
        access_token_uri => $config->{'token_endpoint'},
    );
}

sub relay {
    my ($self, $c) = @_;
    return $c->render('providers/microsoft/relay.tt');
}

sub callback {
    my ($self, $c) = @_;

    my $req = $c->req;

    use Data::Dumper;
    warn Dumper($req);

    # state valdation
    my $state = $req->param('state');
    my $session_state = 
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{Microsoft});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/microsoft/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    return $c->render('providers/microsoft/top.tt');
}

1;
