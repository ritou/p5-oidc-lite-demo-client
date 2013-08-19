use strict;
use warnings;
use utf8;
use Test::More;
use OIDC::Lite::Demo::Client;

my $c = OIDC::Lite::Demo::Client->new;
ok( $c->config->{'DBI'}, "config->{'DBI'}");
ok( $c->config->{'Credentials'}, "config->{'Credentials'}");
ok( $c->config->{'Credentials'}->{'Google'}, "config->{'Credentials'}->{'Google'}");
ok( $c->config->{'Credentials'}->{'Google'}->{'client_id'}, 
    "config->{'Credentials'}->{'Google'}->{'client_id'}");
ok( $c->config->{'Credentials'}->{'Google'}->{'client_secret'}, 
    "config->{'Credentials'}->{'Google'}->{'client_secret'}");
ok( $c->config->{'Credentials'}->{'Google'}->{'redirect_uri'}, 
    "config->{'Credentials'}->{'Google'}->{'redirect_uri'}");
ok( $c->config->{'Credentials'}->{'Google'}->{'scope'}, 
    "config->{'Credentials'}->{'Google'}->{'scope'}");

done_testing;
