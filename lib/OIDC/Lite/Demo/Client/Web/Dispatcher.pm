package OIDC::Lite::Demo::Client::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use Amon2::Web::Dispatcher::Lite;
# Servers
use OIDC::Lite::Demo::Client::Web::C::IDIT;
use OIDC::Lite::Demo::Client::Web::C::Sample;
use OIDC::Lite::Demo::Client::Web::C::Google;

# top
any '/' => sub {
    my ($c) = @_;
    return $c->render('index.tt');
};

# Sample client for ID&IT 2013 Hands On
get '/idit2013' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::IDIT->default($c)
};

get '/idit2013/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::IDIT->authorize($c)
};

get '/idit2013/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::IDIT->callback($c)
};

# Sample client for OIDC::Lite::Demo::Server
get '/sample' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Sample->default($c)
};

get '/sample/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Sample->authorize($c)
};

get '/sample/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Sample->callback($c)
};

# Google demo client
get '/google' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Google->default($c)
};

get '/google/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Google->authorize($c)
};

get '/google/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Google->callback($c)
};

# Google id_token validator
any '/google/id_token' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Google->id_token($c)
};

1;
