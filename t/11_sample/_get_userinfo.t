use strict;
use warnings;
use utf8;
use Test::More;
use Test::MockObject;
use OIDC::Lite::Demo::Client::Web::C::Sample;
use JSON qw/encode_json/;

Test::MockObject->fake_module(
    'LWP::UserAgent',
    'new' => sub{bless {}, shift},
    'request' => sub {
        my ($class, $req) = @_;
        my $content = encode_json({ header => $req->header('Authorization') });
        my $res = HTTP::Response->new(200, '', undef, $content);
    },
);

_GET_USERINFO: {
    my $access_token = q{abcdefg};
    my $res = 
        OIDC::Lite::Demo::Client::Web::C::Sample->_get_userinfo( $access_token );
    is( $res->content, "{\"header\":\"Bearer abcdefg\"}", q{access_token is set to request})
};

done_testing;
