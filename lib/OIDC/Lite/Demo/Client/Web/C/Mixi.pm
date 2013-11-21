package OIDC::Lite::Demo::Client::Web::C::Mixi;

use strict;
use warnings;
use utf8;

use OIDC::Lite::Demo::Client::Session;
use OIDC::Lite::Client::WebServer;
use OIDC::Lite::Model::IDToken;
use JSON qw/encode_json decode_json/;
use Crypt::OpenSSL::CA;

my $config = {
    'authorization_endpoint' => 'https://mixi.jp/connect_authorize.pl',
    'token_endpoint' => 'https://secure.mixi-platform.com/2/token',
    'userinfo_endpoint' => 'https://api.mixi-platform.com/2/openid/userinfo',
};

sub default {
    my ($self, $c) = @_;
    return $c->render('providers/mixi/top.tt');
}

sub authorize {
    my ($self, $c) = @_;

    my $mixi_config = $c->config->{'Credentials'}->{'Mixi'};
    my $client = $self->_client( $mixi_config );
    my $server_state = $client->get_server_state();
    my $res = $client->last_response;
    unless ($server_state) {
        return $c->render('providers/mixi/error.tt' => {
            message => q{Failed to get Server State response},
            code => $res->code,
            content => $res->content,
            request_uri => $res->request->uri,
            request_body => $res->request->content,
        });
    }

    OIDC::Lite::Demo::Client::Session->set_server_state($c->session, q{Mixi}, $server_state->server_state);

    # generate and save state parameter to session
    my $state = OIDC::Lite::Demo::Client::Session->generate_state($c->session, q{Mixi});
    OIDC::Lite::Demo::Client::Session->set_state($c->session, q{Mixi}, $state);

    # build authorize request
    my $uri = $self->_uri_to_authorizatin_endpoint( $mixi_config, $state, $server_state->server_state );

    #return $c->redirect($uri);
    return $c->render('providers/mixi/authreqest.tt' => {
        code => $res->code,
        content => $res->content,
        request_uri => $res->request->uri,
        request_body => $res->request->content,
        authorization_request => $uri,
    });
}

sub _uri_to_authorizatin_endpoint {
    my ($self, $mixi_config, $state, $server_state) = @_;

    return $self->_client( $mixi_config )->uri_to_redirect(
        redirect_uri => $mixi_config->{'redirect_uri'},
        scope        => $mixi_config->{'scope'},
        state        => $state,
        extra        => {
            server_state => $server_state,
        },
    );
}

sub _client {
    my ($self, $mixi_config) = @_;

    return OIDC::Lite::Client::WebServer->new(
        id               => $mixi_config->{'client_id'},
        secret           => $mixi_config->{'client_secret'},
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
        OIDC::Lite::Demo::Client::Session->get_state($c->session, q{Mixi});

    unless ($state && $session_state && $state eq $session_state) {
        # invalid state
        return $c->render('providers/mixi/error.tt' => {
            message => q{The state parameter is missing or not matched with session.},
        });
    }

    # code
    my $code = $req->param('code');
    unless ($code) {
        # invalid state
        return $c->render('providers/mixi/error.tt' => {
            message => q{The code parameter is missing.},
        });
    }

    # prepare access token request
    my $mixi_config = $c->config->{'Credentials'}->{'Mixi'};
    my $client = $self->_client( $mixi_config );
    my $server_state = 
        OIDC::Lite::Demo::Client::Session->get_server_state($c->session, q{Mixi}) or
        return $c->render('providers/mixi/error.tt' => {
            message => q{This session doesn't server_state for authorization.},
        });

    # get_access_token
    my $token = $client->get_access_token(
        code         => $code,
        redirect_uri => $mixi_config->{'redirect_uri'},
        server_state => $server_state,
    );
    OIDC::Lite::Demo::Client::Session->set_server_state($c->session, q{Mixi}, q{});
    my $res = $client->last_response;
    my $request_body = $res->request->content;
    $request_body =~ s/client_secret=[^\&]+/client_secret=(hidden)/;

    unless ($token) {
        return $c->render('providers/mixi/error.tt' => {
            message => q{Failed to get access token response},
            code => $res->code,
            content => $res->content,
            request_uri => $res->request->uri,
            request_body => $request_body,
        });
    }
    my $response_body = $res->content;
    $response_body =~ s/"access_token":"[^\&]+"/"access_token":"(hidden)"/;
    my $info = {
        token_request_uri => $res->request->uri,
        token_request_body => $request_body,
        token_response_code => $res->code,
        token_response_body => $response_body,
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
        return $c->render('providers/mixi/error.tt' => {
            message => q{Failed to get userinfo response},
            code => $userinfo_res->code,
            content => $userinfo_res->content,
            request_uri => $userinfo_res->request->uri,
        });
    }
    $info->{'userinfo_endpoint'} = $config->{'userinfo_endpoint'};
    $info->{'userinfo_request_header'} = $userinfo_res->request->header('Authorization');
    $info->{'userinfo_response_code'} = $userinfo_res->code;
    $info->{'userinfo_response_body'} = $userinfo_res->content;

    # display result
    return $c->render('providers/mixi/authorized.tt' => {
        info => $info,
    });
}

sub _get_userinfo {
    my ($self, $access_token) = @_;

    my $req = HTTP::Request->new( GET => $config->{'userinfo_endpoint'} );
    $req->header( Authorization => sprintf(q{Bearer %s}, $access_token) );
    return LWP::UserAgent->new->request($req);
}

sub id_token {
    my ($self, $c) = @_;

    my $result;
    my $id_token;
    my $req = $c->req;

    if( $req->method eq q{POST} ) {
        $id_token = $req->param('id_token');
        $result = $self->_validate_id_token( $id_token );
    }

    # validate payload
    if ( $result->{payload} ) {
        $result->{payload_detail} = $self->_validate_id_token_payload( 
                                        $result->{payload}, 
                                        $c->config->{'Credentials'}->{'Mixi'}
                                    );
    }

    return $c->render('providers/mixi/id_token.tt' => {
        id_token => $id_token,
        result => $result,
    });
}

sub _validate_id_token {
    my ($self, $id_token_string) = @_;

    my $result = {
        id_token_string => $id_token_string,
        signature_status => 0,
    };

    # load IDToken Object
    my $id_token = OIDC::Lite::Model::IDToken->load( $result->{id_token_string} );
    if ( $id_token ) {

        my $encoded = [split(/\./, $result->{id_token_string})];
        ($result->{encoded_header}, $result->{encoded_payload}, $result->{encoded_signature}) = @$encoded;
        $result->{signing_input} = $result->{encoded_header}.'.'.$result->{encoded_payload};

        # Google's ID Token has kid param in header.
        return $result 
            unless (    $id_token->header->{alg} && 
                        $id_token->header->{alg} eq q{RS256} &&
                        $id_token->header->{kid} );
        $result->{header_content} = encode_json( $id_token->header );

        # fetch pubkey and verify signature
        my $key = $self->_get_pub_key( $id_token->header->{kid} );
        return $result unless $key;
        $result->{pubkey} = $key;
        $id_token->key($key);
        return $result unless $id_token->verify;

        $result->{signature_status} = 1;
        $result->{payload_content} = encode_json( $id_token->payload );
        # for payload validation
        $result->{payload} = $id_token->payload;
    }

    return $result;
}

sub _get_pub_key {
    my ( $self, $kid ) = @_;
    
    my $pub_key;

    my $cert = << "__CERT__";
-----BEGIN CERTIFICATE-----
MIIDNzCCAh+gAwIBAgIJAJjXIVKEYTpLMA0GCSqGSIb3DQEBBQUAMDIxCzAJBgNV
BAYTAkpQMREwDwYDVQQKDAhtaXhpIEluYzEQMA4GA1UEAwwHbWl4aS5qcDAeFw0x
MzExMTUwNjA1NDlaFw0yMzExMTMwNjA1NDlaMDIxCzAJBgNVBAYTAkpQMREwDwYD
VQQKDAhtaXhpIEluYzEQMA4GA1UEAwwHbWl4aS5qcDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANhIUPkNC+lutt0/wWUUBB4F0Zwu5aLMHTdy9cz4Gc85
hmjKKwq7VdNo/ZLFZv1vtsR+kYymeMgNe2bAItPt99GLONsFx+v7DjwGYz2qTwdI
3HfiDyyUuW9nPEf7F0MthdlqmgSLVPhfU9uXOKIOKtK5QlRoPJTvIckr6CmSd90L
3dtfiOBFDEqUjJzZHomJ1L6Wt/Qv1vMV9YWkLzWjmtneWLkrfUAi5H8MVViDwRvh
jmYhN1wG8wn7g3/CL7cOZ7AdhY25e82p9ZG3Q7xcr+GaxPEe3uNDKvBSka+F8TKV
NezI3FLIauzR5n+dcWTe0AqYFDLqrzPaWfT21xPy54MCAwEAAaNQME4wHQYDVR0O
BBYEFKpfIm0r4dOUjP4vUSmLqTnpyloxMB8GA1UdIwQYMBaAFKpfIm0r4dOUjP4v
USmLqTnpyloxMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJPT65qT
7isKxk+xmfkg5Hr2lPP0XesRFtdzt+2OIdFdenBF3viCLV5KF+4kV70dA02mDiUV
eoVu0ykxTT91MmQwM4A18F0OuZgVDQ9XbFBbf/Awd08PW2+8de84+NGh7XyqTgn/
0yTRCIYAKwg4oh/fE1FQhHDtdAtiPjZOlTdSmzHSWR4qcnAKyN7fshdtS1NSKflR
YAhnU+4d1veR26MGrjwGR9g0GxOZthvi35Mzz/YnKrbzXDCQZubw7Qd+EU5Q40UV
dtAKBpWVPzJBYt+iZGlYvlqQ9uMS950Eh8Ql74WW1qohHCq5Vo+yxSg+qlk6UYtf
OrYAVnC1QJoxZb8=
-----END CERTIFICATE-----
__CERT__

    eval {
        $pub_key = Crypt::OpenSSL::CA::X509->parse($cert)->get_public_key->to_PEM;
    };
    return if $@;

    return $pub_key;
}

sub _validate_id_token_payload {
    my ( $self, $payload, $config ) = @_;
    my $detail = {
        status => 0,
    };

    # iss
    $detail->{iss} = $payload->{iss};
    unless ( $payload->{iss} ) {
        $detail->{message} = q{iss does not exist};
        return $detail;
    }
    unless ( $payload->{iss} eq q{https://api.mixi-platform.com} ) {
        $detail->{message} = q{iss is not Mixi};
        return $detail;
    }

    # iat
    $detail->{current} = time();
    $detail->{iat} = $payload->{iat};
    unless ( $payload->{iat} ) {
        $detail->{message} = q{iat does not exist};
        return $detail;
    }
    my $now = time();
    unless ( $payload->{iat} <= $now ) {
        $detail->{message} = q{iat is greater than current timestamp};
        return $detail;
    }

    # exp
    $detail->{exp} = $payload->{exp};
    unless ( $payload->{exp} ) {
        $detail->{message} = q{exp does not exist};
        return $detail;
    }
    unless ( $payload->{exp} >= $now ) {
        $detail->{message} = q{exp is not greater than current timestamp};
        return $detail;
    }

    # aud
    $detail->{aud} = $payload->{aud};
    $detail->{client_id} = $config->{client_id};
    unless ( $payload->{aud} || $payload->{azp} ) {
        $detail->{message} = q{aud does not exist};
        return $detail;
    }
    unless ( $payload->{aud} eq $config->{client_id} ) {
        $detail->{message} = q{aud does not match with this app's client_id};
        return $detail;
    }

    $detail->{status} = 1;
    $detail->{userinfo} = encode_json({
        sub => $payload->{sub},
    });

    return $detail;
}

1;
