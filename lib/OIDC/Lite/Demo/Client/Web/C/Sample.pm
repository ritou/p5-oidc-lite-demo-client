package OIDC::Lite::Demo::Client::Web::C::Sample;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OIDC::Lite::Client::WebServer;
use OIDC::Lite::Model::IDToken;
use JSON qw/encode_json decode_json/;

my $config = {
    'authorization_endpoint' => 'http://localhost:5001/authorize',
    'token_endpoint' => 'http://localhost:5001/token',
    'userinfo_endpoint' => 'http://localhost:5001/userinfo',
};

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/sample/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{Sample});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{Sample}, $state);

    # build authorize request URL
    my $sample_config = $c->config->{'Credentials'}->{'Sample'};
    my $uri = $self->_uri_to_sample_authorizatin_endpoint( $sample_config, $state );

    return $c->redirect($uri);
}

sub _uri_to_sample_authorizatin_endpoint {
    my ($self, $sample_config, $state) = @_;

    return $self->_client( $sample_config )->uri_to_redirect(
        redirect_uri => $sample_config->{'redirect_uri'},
        scope        => $sample_config->{'scope'},
        state        => $state,
    );
}

sub _client {
    my ($self, $sample_config) = @_;

    return OIDC::Lite::Client::WebServer->new(
        id               => $sample_config->{'client_id'},
        secret           => $sample_config->{'client_secret'},
        authorize_uri    => $config->{'authorization_endpoint'},
        access_token_uri => $config->{'token_endpoint'},
    );
}

sub callback {
    my ($self, $c) = @_;

    my $req = $c->req;

    # state valdation
    my $state = $req->param('state');
    my $session_state = 
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{Sample});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/sample/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    # code
    my $code = $req->param('code');
    unless ($code) {
        # invalid state
        return $c->render('providers/sample/error.tt' => {
            message => q{The code parameter is missing.},
        });
    }

    # prepare access token request
    my $sample_config = $c->config->{'Credentials'}->{'Sample'};
    my $client = $self->_client( $sample_config );

    # get_access_token
    my $token = $client->get_access_token(
        code         => $code,
        redirect_uri => $sample_config->{'redirect_uri'},
    );
    my $res = $client->last_response;
    my $request_body = $res->request->content;
    $request_body =~ s/client_secret=[^\&]+/client_secret=(hidden)/;

    unless ($token) {
        return $c->render('providers/sample/error.tt' => {
            message => q{Failed to get access token response},
            code => $res->code,
            content => $res->content,
            request => $request_body,
        });
    }
    my $info = {
        token_request => $request_body,
        token_response => $res->content,
    };

    # ID Token validation
    my $id_token = OIDC::Lite::Model::IDToken->load($token->id_token);
    $info->{'id_token'} = {
        header => encode_json( $id_token->header ),
        payload => encode_json( $id_token->payload ),
        string => $id_token->token_string,
    };

    # get_user_info
    my $userinfo_res = $self->_get_userinfo( $token->access_token );
    unless ($userinfo_res->is_success) {
        return $c->render('providers/sample/error.tt' => {
            message => q{Failed to get userinfo response},
            code => $userinfo_res->code,
            content => $userinfo_res->content,
        });
    }
    $info->{'userinfo_endpoint'} = $config->{'userinfo_endpoint'};
    $info->{'userinfo_request_header'} = $userinfo_res->request->header('Authorization');
    $info->{'userinfo_response'} = $userinfo_res->content;

    # display result
    return $c->render('providers/sample/authorized.tt' => {
        info => $info,
    });
}

sub _get_userinfo {
    my ($self, $access_token) = @_;

    my $req = HTTP::Request->new( GET => $config->{'userinfo_endpoint'} );
    $req->header( Authorization => sprintf(q{Bearer %s}, $access_token) );
    return LWP::UserAgent->new->request($req);
}

1;
