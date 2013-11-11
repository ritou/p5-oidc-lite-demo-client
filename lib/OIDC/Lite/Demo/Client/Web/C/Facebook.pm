package OIDC::Lite::Demo::Client::Web::C::Facebook;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OIDC::Lite::Client::WebServer;
use URI;
use URI::QueryParam;

my $config = {
    'authorization_endpoint' => 'https://www.facebook.com/dialog/oauth',
    'token_endpoint' => 'https://graph.facebook.com/oauth/access_token',
    'userinfo_endpoint' => 'https://graph.facebook.com/me',
};

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/facebook/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{Facebook});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{Facebook}, $state);

    # build authorize request URL
    my $facebook_config = $c->config->{'Credentials'}->{'Facebook'};
    my $uri = $self->_uri_to_facebook_authorization_endpoint( $facebook_config, $state );

    return $c->redirect($uri);
}

sub _uri_to_facebook_authorization_endpoint {
    my ($self, $facebook_config, $state) = @_;

    return $self->_client( $facebook_config )->uri_to_redirect(
        redirect_uri => $facebook_config->{'redirect_uri'},
        scope        => $facebook_config->{'scope'},
        state        => $state,
        extra        => {
            access_type => q{offline},
        },
    );
}

sub _client {
    my ($self, $facebook_config) = @_;

    return OIDC::Lite::Client::WebServer->new(
        id               => $facebook_config->{'client_id'},
        secret           => $facebook_config->{'client_secret'},
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
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{Facebook});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/facebook/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    # code
    my $code = $req->param('code');
    unless ($code) {
        # invalid state
        return $c->render('providers/facebook/error.tt' => {
            message => q{The code parameter is missing.},
        });
    }

    # prepare access token request
    my $facebook_config = $c->config->{'Credentials'}->{'Facebook'};
    my $client = $self->_client( $facebook_config );

    # get_access_token
    my $token = $client->get_access_token(
        code         => $code,
        redirect_uri => $facebook_config->{'redirect_uri'},
    );
    my $res = $client->last_response;
    my $request_body = $res->request->content;
    $request_body =~ s/client_secret=[^\&]+/client_secret=(hidden)/;

    unless ($token) {
        return $c->render('providers/facebook/error.tt' => {
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

    my $access_token = $token->access_token or die "no access_token?!";

    # get_user_info
    my $userinfo_res = $self->_get_userinfo( $access_token );
    unless ($userinfo_res->is_success) {
        return $c->render('providers/facebook/error.tt' => {
            message => q{Failed to get userinfo response},
            code => $userinfo_res->code,
            content => $userinfo_res->content,
        });
    }
    $info->{'userinfo_endpoint'} = $config->{'userinfo_endpoint'};
    $info->{'userinfo_request_header'} = $userinfo_res->request->header('Authorization');
    $info->{'userinfo_response'} = $userinfo_res->content;

    # display result
    return $c->render('providers/facebook/authorized.tt' => {
        info => $info,
    });
}

sub _get_userinfo {
    my ($self, $access_token) = @_;

    my $uri = URI->new($config->{'userinfo_endpoint'});
    $uri->query_param(access_token => $access_token);

    my $req = HTTP::Request->new( GET => $uri );
    return LWP::UserAgent->new->request($req);
}


1;
