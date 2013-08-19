use strict;
use warnings;
use utf8;
use Test::More;
use Test::MockObject;
use Plack::Session;
use OIDC::Lite::Demo::Client::Controller::Google;

_AUTHORIZE: {
    Test::MockObject->fake_module(
        'OIDC::Lite::Demo::Client',
        'new' => sub{bless {}, shift},
        'session' => sub {
            return Plack::Session->new({
                'psgix.session' => +{},    
                'psgix.session.options' => +{},    
            });
        },
        'config' => sub {
            return {
                'Credentials' => {
                    'Google' => {
                        'client_id' => q{aaa},
                        'client_secret' => q{bbb},
                        'redirect_uri' => q{http://localhost:5000/google/callback},
                        'scope' => q{openid email profile},
                    },
                },
            };
        },
        'redirect' => sub{
            my ($class, $url) = @_;
            return "redirect : ".$url;
        },
    );
    Test::MockObject->fake_module(
        'OIDC::Lite::Demo::Client::Session',
        'generate_state' => sub {
            return q{state_string};
        },
        'set_state' => sub {
            return;
        },
    );

    my $c = OIDC::Lite::Demo::Client->new();
    my $res = OIDC::Lite::Demo::Client::Controller::Google->authorize($c);
    like ($res, qr/\Aredirect : https:\/\/accounts\.google\.com\/o\/oauth2\/auth/);
    like ($res, qr/client_id=aaa/);
    like ($res, qr/response_type=code/);
    like ($res, qr/redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fgoogle%2Fcallback/);
    like ($res, qr/access_type=offline/);
    like ($res, qr/scope=openid\+email\+profile/);
    like ($res, qr/state=state_string/);
};

done_testing;
