package OIDC::Lite::Demo::Client::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use Amon2::Web::Dispatcher::Lite;
# Strategy
use OIDC::Lite::Demo::Client::Controller::Google;

# top
any '/' => sub {
    my ($c) = @_;
    return $c->render('index.tt');
};

# Google demo client
get '/google' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Controller::Google->default($c)
};

get '/google/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Controller::Google->authorize($c)
};

get '/google/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Controller::Google->callback($c)
};

# Google id_token validator
any '/google/id_token' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Controller::Google->id_token($c)
};

1;
