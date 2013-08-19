use strict;
use warnings;
use utf8;
use Test::More;
use Test::MockObject;
use OIDC::Lite::Demo::Client::Controller::Google;
use JSON::XS qw/encode_json/;

my $content = {
    "5404196e2d38cca061bc51a55a04bc24c1612184"=> "-----BEGIN CERTIFICATE-----
MIICITCCAYqgAwIBAgIISRO2z3PNykkwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE
AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe
Fw0xMzA4MjIwODQzMzRaFw0xMzA4MjMyMTQzMzRaMDYxNDAyBgNVBAMTK2ZlZGVy
YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAKcAil30dwXY/IvZp63BsDT+ds9YlZRnzLHqDcqV
jwVD6oSUAoZWtRaTv7VDCw14n43hn0xNbJQVVZinwBEukNMrVUAJjaXbMZcPFOm/
4ZTGRxPyBCjDovHXdvMUffXXIKRGrtYJ0V5uap7q0A5uivmFM/V0kGzXT7SetW5N
o5bBAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
JQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBADJWRkLX57M7JCfR
rfxX6TKfuHd50jqTS20si5zoYKZNCqpdVJbWNiXTFmCbOCXnBMhqxdq5UZARZhjX
mjze5l4t6Z9k1KmSieJlIM5705PO87xn2ywkBSMGP8Yc5/hTltWdZlXDay1TDrHP
TuDVYQTK/BL2ixH1+sHczdBhuJeu
-----END CERTIFICATE-----",
    "07f6fe44e331d161e238c06ff722bca2c79b82b2"=> "-----BEGIN CERTIFICATE-----
MIICITCCAYqgAwIBAgIICChYKXpgHMswDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE
AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe
Fw0xMzA4MjMwODI4MzRaFw0xMzA4MjQyMTI4MzRaMDYxNDAyBgNVBAMTK2ZlZGVy
YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAKAk+oPdAJO5jiAPRi3ocyCYQ/fIsrIvnK8RCPQz
K8QKMHWiycBqWq35cqtu007v/UlgVcE8I4ttMKUceifCTiaUAIA67ydBJSo90g9w
+y4925g4j+EnyrDyAeOPJkDdEuxeLduoqRjQEieNOkOXiF5m9AHVh0OYylKpLD9z
XIBfAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
JQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4GBABk2MonJ0Aj5cLct
JsTM80B5JRnUGYXgHH7avtg1qXc/P1pIBZOMj49luWvDnvD0CPU2+Q1vtTtLRRbU
vaoOg9VEJTR+r8hQ7/9s5kESp9c4cvCUqXB33QGalLAMtaIw8d4aqzFIBuJRRYVW
8sA1wxL8d8BuCtjPFCmXCmlP1i/B
-----END CERTIFICATE-----",
    "invalid_key" => "invalid",
};
my $content_is_not_json = q{not json string};

_GET_GOOGLE_PUB_KEY: {
    Test::MockObject->fake_module(
        'LWP::UserAgent',
        'new' => sub{bless {}, shift},
        'request' => sub {
            my ($class, $req) = @_;
            return HTTP::Response->new(400, '', undef, undef);
        },
    );
    my $pub = 
        OIDC::Lite::Demo::Client::Controller::Google->_get_google_pub_key("dummy");
    ok( !$pub, q{HTTP status code is not ok});

    Test::MockObject->fake_module(
        'LWP::UserAgent',
        'new' => sub{bless {}, shift},
        'request' => sub {
            my ($class, $req) = @_;
            return HTTP::Response->new(200, '', undef, $content_is_not_json);
        },
    );
    $pub = OIDC::Lite::Demo::Client::Controller::Google->_get_google_pub_key("dummy");
    ok( !$pub, q{content is not json});

    Test::MockObject->fake_module(
        'LWP::UserAgent',
        'new' => sub{bless {}, shift},
        'request' => sub {
            my ($class, $req) = @_;
            my $res = HTTP::Response->new(200, '', undef, encode_json($content));
        },
    );
    $pub = OIDC::Lite::Demo::Client::Controller::Google->_get_google_pub_key("invalid_key");
    ok( !$pub, q{pubkey is not PEM});

    $pub = OIDC::Lite::Demo::Client::Controller::Google->_get_google_pub_key("5404196e2d38cca061bc51a55a04bc24c1612184");
    ok( $pub, q{pubkey returned});
    use Data::Dumper;
    like( $pub, qr/-----BEGIN PUBLIC KEY-----/, q{-----BEGIN PUBLIC KEY-----});
    like( $pub, qr/-----END PUBLIC KEY-----/, q{-----END PUBLIC KEY-----});
};

_VALIDATE_GOOGLE_ID_TOKEN: {
    Test::MockObject->fake_module(
        'LWP::UserAgent',
        'new' => sub{bless {}, shift},
        'request' => sub {
            my ($class, $req) = @_;
            my $res = HTTP::Response->new(200, '', undef, encode_json($content));
        },
    );

    # not JWS
    my $id_token = q{This is not JWS string};
    my $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # no alg
    $id_token = q{eyJmb28iOiJiYXIifQ.eyJmb28iOiJiYXIifQ.invalid_signature};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # alg is invalid
    $id_token = q{eyJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.invalid_signature};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # no kid
    $id_token = q{eyJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.invalid_signature};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # invalid kid
    $id_token = q{eyJhbGciOiJSUzI1NiIsImtpZCI6ImludmFsaWQifQ.eyJmb28iOiJiYXIifQ.invalid_signature};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # invalid signature
    $id_token = q{eyJhbGciOiJSUzI1NiIsImtpZCI6IjU0MDQxOTZlMmQzOGNjYTA2MWJjNTFhNTVhMDRiYzI0YzE2MTIxODQifQ.eyJmb28iOiJiYXIifQ.invalid_signature};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( !$result->{signature_status}, q{signature status is invalid});
    ok( !$result->{payload_content}, q{payload});
    ok( !$result->{payload}, q{payload});

    # valid signature
    $id_token = q{eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3ZjZmZTQ0ZTMzMWQxNjFlMjM4YzA2ZmY3MjJiY2EyYzc5YjgyYjIifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6IjlsYnRlUlpoWmppVjQ0SU45Q3Y0eFEiLCJhdWQiOiIxMDU4NDIxMzE0OTY2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE0MTgxMzA4NzI1NzMwOTg1MjM3IiwiZW1haWwiOiJyaXRvdS4wNkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJhenAiOiIxMDU4NDIxMzE0OTY2LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaWF0IjoxMzc3Mjc2OTIzLCJleHAiOjEzNzcyODA4MjN9.VagTki3Ap29EDgrC38cmGtZeoZdPJjPH4f_475Nd2FVa84HQDkSrO4-3r-2sxco_Z8DWi_i-AlHLHC01JTmOg69inwAWQ2usPV9gkcNLt5PMKKc3TkfB5WM6R5lNz-H6NHVldVkV1GHKTBFoFs4lwyE83ko41EHdHKxmgj9L5cM};
    $result = OIDC::Lite::Demo::Client::Controller::Google->_validate_google_id_token( $id_token );
    ok( $result, q{result is returned});
    ok( $result->{signature_status}, q{signature status is valid});
    ok( $result->{payload_content}, q{payload});
    ok( $result->{payload}, q{payload});
};

done_testing;
