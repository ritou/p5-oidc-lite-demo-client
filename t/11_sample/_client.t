use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client::Web::C::Sample;

_CLIENT: {
    my $sample_config = {
        'client_id' => q{aaa},
        'client_secret' => q{bbb},
        'redirect_uri' => q{http://localhost:5000/sample/callback},
        'scope' => q{openid email profile phone address},
    };
    my $client = 
        OIDC::Lite::Demo::Client::Web::C::Sample->_client( $sample_config );
    ok( $client, q{object is returned} );
    isa_ok( $client, q{OIDC::Lite::Client::WebServer}, q{OIDC::Lite::Client::WebServer} );
};

done_testing;
