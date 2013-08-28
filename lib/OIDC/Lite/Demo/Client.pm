package OIDC::Lite::Demo::Client;
use strict;
use warnings;
use utf8;
use parent qw/Amon2/;
use 5.008001;
our $VERSION = '0.01';

__PACKAGE__->load_plugin(qw/DBI/);

# initialize database
use DBI;
sub setup_schema {
    my $self = shift;
    my $dbh = $self->dbh();
    my $driver_name = $dbh->{Driver}->{Name};
    my $fname = lc("sql/${driver_name}.sql");
    open my $fh, '<:encoding(UTF-8)', $fname or die "$fname: $!";
    my $source = do { local $/; <$fh> };
    for my $stmt (split /;/, $source) {
        next unless $stmt =~ /\S/;
        $dbh->do($stmt) or die $dbh->errstr();
    }
}

use Teng;
use Teng::Schema::Loader;
use OIDC::Lite::Demo::Client::DB;
my $schema;
sub db {
    my $self = shift;
    if ( !defined $self->{db} ) {
        my $conf = $self->config->{'DBI'}
        or die "missing configuration for 'DBI'";
        my $dbh = DBI->connect(@{$conf});
        if ( !defined $schema ) {
            $self->{db} = Teng::Schema::Loader->load(
                namespace => 'OIDC::Lite::Demo::Client::DB',
                dbh       => $dbh,
	    );
            $schema = $self->{db}->schema;
        } else {
            $self->{db} = OIDC::Lite::Demo::Client::DB->new(
                dbh    => $dbh,
                schema => $schema,
	    );
        }
    }
    return $self->{db};
}

1;
__END__

=head1 NAME

OIDC::Lite::Demo::Client - OpenID Connect Demo Client using OIDC::Lite

=head1 DESCRIPTION

OpenID Connect Demo Client using OIDC::Lite

=head1 SYNOPSIS

    # 0. obtain src and carton setup
    $ git clone https://github.com/ritou/p5-oidc-lite-demo-client.git
    $ cd p5-oidc-lite-demo-client
    
    # 1. Build and test
    $ perl Build.pl
    $ ./Build test
    
    # 2. Modify your app's configuration
    # The case of Google, 
    # Visit to https://code.google.com/apis/console/ and register your app.
    # Replace client_id and client_secret, redirect_uri with sample configuration.
    $ vim config/development.pl
    
    # 3. Run your demo client
    $ plackup -r

If you are able to use carton, following command are needed.

    # 0. obtain src and carton setup
    $ git clone https://github.com/ritou/p5-oidc-lite-demo-client.git
    $ cd p5-oidc-lite-demo-client
    $ carton install
    
    # 1. Build and test
    $ carton exec perl Build.pl
    $ carton exec ./Build test
    
    # 2. Modify your app's configuration
    # The case of Google, 
    # Visit to https://code.google.com/apis/console/ and register your app.
    # Replace client_id and client_secret, redirect_uri with sample configuration.
    $ vim config/development.pl
    
    # 3. Run your demo client
    $ carton exec plackup -r

When plack is launched, try to access http://localhost:5000/

=head1 AUTHOR

Ryo Ito E<lt>ritou.06@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Ryo Ito

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
