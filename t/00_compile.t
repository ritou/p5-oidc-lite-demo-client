use strict;
use warnings;
use utf8;
use Test::More;

use_ok $_ for qw(
    OIDC::Lite::Demo::Client
    OIDC::Lite::Demo::Client::Web
    OIDC::Lite::Demo::Client::Web::ViewFunctions
    OIDC::Lite::Demo::Client::Web::Dispatcher
);

done_testing;
