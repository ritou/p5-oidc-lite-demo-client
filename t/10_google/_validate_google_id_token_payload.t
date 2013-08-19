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

    $payload = {
       iss => q{accounts.google.com}, 
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no iat} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iat does not exist}, q{iat does not exist} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() + 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{iat is future} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{iat is greater than current timestamp}, q{iat is greater than current timestamp} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no exp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{exp does not exist}, q{exp does not exist} );

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

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{no aud and azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{aud and azp do not exist}, q{aud and azp do not exist} );

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
    is( $result->{message}, q{aud and azp do not match with this app's client_id}, q{aud and azp do not match with this app's client_id} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aab},
       azp => q{aab},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{invalid aud and azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{aud and azp do not match with this app's client_id}, q{aud and azp do not match with this app's client_id} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       azp => q{aab},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{invalid azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{aud and azp do not match with this app's client_id}, q{aud and azp do not match with this app's client_id} );

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

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       azp => q{aaa},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{valid azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );

    $payload = {
       iss => q{accounts.google.com}, 
       iat => (time() - 100),
       exp => (time() + 100),
       aud => q{aaa},
       azp => q{aaa},
    };
    $result = 
        OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token_payload( $payload, $config );
    ok( $result, q{valid aud and azp} );
    ok( !$result->{status}, q{status is invalid} );
    is( $result->{message}, q{sub, email and email_verified do not exist}, q{message} );

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
