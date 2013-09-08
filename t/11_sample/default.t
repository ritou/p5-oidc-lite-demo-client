use strict;
use warnings;
use utf8;
use Test::More;
use Test::MockObject;
use OIDC::Lite::Demo::Client::Web::C::Sample;

_DEFAULT: {
    Test::MockObject->fake_module(
        'OIDC::Lite::Demo::Client',
        'new' => sub{bless {}, shift},
        'render' => sub {
            my ($class, $path) = @_;
            return "render : ".$path;
        },
    );

    my $c = OIDC::Lite::Demo::Client->new();
    my $res = OIDC::Lite::Demo::Client::Web::C::Sample->default($c);
    is($res, q{render : providers/sample/top.tt});
};

done_testing;
