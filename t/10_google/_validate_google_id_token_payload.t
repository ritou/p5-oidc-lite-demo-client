use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Controller::Google;

my $config = {
    'client_id' => q{aaa},
    'client_secret' => q{bbb},
    'redirect_uri' => q{http://localhost:5000/google/callback},
    'scope' => q{openid email profile},
};

_VALIDATE_PAYLOAD: {
    my $payload = +{};

    my $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no iss} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iss does not exist}, q{iss does not exist} );

    $payload = {
       iss => q{this.is.not.google}, 
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{invalid iss} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iss is not Google}, q{iss is not Google} );
    is( $result->{iss}, $payload->{iss}, q{iss is set} );

    $payload = {
       iss => q{accounts.google.com}, 
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no iat} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iat does not exist}, q{iat does not exist} );
    ok( !$result->{iat}, q{iat is not set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() + 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{iat is future} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iat is greater than current timestamp}, q{iat is greater than current timestamp} );
    is( $result->{iat}, $payload->{iat}, q{iat is set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no exp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{exp does not exist}, q{exp does not exist} );
    ok( !$result->{exp}, q{exp is not set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() - 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{expired} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{exp is not greater than current timestamp}, q{exp is not greater than current timestamp} );
    is( $result->{exp}, $payload->{exp}, q{exp is set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no aud and azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{aud does not exist}, q{aud does not exist} );
    ok( !$result->{aud}, q{aud is not set} );
    is( $result->{client_id}, $config->{client_id}, q{client_id is set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aab},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{invalid aud} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{aud does not match with this app's client_id}, q{aud does not match with this app's client_id} );
    is( $result->{aud}, $payload->{aud}, q{aud is set} );
    is( $result->{client_id}, $config->{client_id}, q{client_id is set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{valid aud} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );
    is( $result->{aud}, $payload->{aud}, q{aud is set} );
    is( $result->{client_id}, $config->{client_id}, q{client_id is set} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
       azp => q{aaa},
       email => q{user@example.com},
       email_verified => 1,
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no sub} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
       azp => q{aaa},
       sub => q{user_id},
       email_verified => 1,
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no email} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
       azp => q{aaa},
       sub => q{user_id},
       email => q{user@example.com},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no email_verified} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
       azp => q{aaa},
       sub => q{user_id},
       email => q{user@example.com},
       email_verified => 1,
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no email_verified} );
    ok( $result->{status}, q{status is invalid} );
    ok( !$result->{message}, q{no message} );
    ok( $result->{userinfo}, q{userinfo is set} );
    like( $result->{userinfo}, qr/\"sub\":\"user_id\"/, q{userinfo sub} );
    like( $result->{userinfo}, qr/\"email\":\"user\@example.com\"/, q{userinfo email} );
    like( $result->{userinfo}, qr/\"email_verified\":1/, q{userinfo email_verified} );
};

done_testing;
