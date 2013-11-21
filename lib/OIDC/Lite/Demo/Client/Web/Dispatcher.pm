package OIDC::Lite::Demo::Client::Web::Dispatcher;
use strict;
use warnings;
use utf8;
use Amon2::Web::Dispatcher::Lite;
# Servers
use OIDC::Lite::Demo::Client::Web::C::Sample;
use OIDC::Lite::Demo::Client::Web::C::Google;
use OIDC::Lite::Demo::Client::Web::C::Facebook;
use OIDC::Lite::Demo::Client::Web::C::Microsoft;
use OIDC::Lite::Demo::Client::Web::C::YahooJapan;
use OIDC::Lite::Demo::Client::Web::C::Mixi;

# top
any '/' => sub {
    my ($c) = @_;
    return $c->render('index.tt');
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


# Facebook demo client
get '/facebook' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Facebook->default($c)
};

get '/facebook/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Facebook->authorize($c)
};

get '/facebook/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Facebook->callback($c)
};


# Microsoft demo client
get '/microsoft' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Microsoft->default($c)
};

get '/microsoft/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Microsoft->authorize($c)
};

get '/microsoft/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Microsoft->callback($c)
};

# Microsoft id_token validator
any '/microsoft/id_token' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Microsoft->id_token($c)
};

# Yahoo Japan demo client
get '/yahoo_japan' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::YahooJapan->default($c)
};

get '/yahoo_japan/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::YahooJapan->authorize($c)
};

get '/yahoo_japan/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::YahooJapan->callback($c)
};

# YahooJapan id_token validator
any '/yahoo_japan/id_token' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::YahooJapan->id_token($c)
};

# mixi demo client
get '/mixi' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Mixi->default($c)
};

get '/mixi/authorize' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Mixi->authorize($c)
};

get '/mixi/callback' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Mixi->callback($c)
};

# mixi id_token validator
any '/mixi/id_token' => sub {
    my ($c) = @_;
    return OIDC::Lite::Demo::Client::Web::C::Mixi->id_token($c)
};

1;
