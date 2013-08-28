# NAME

OIDC::Lite::Demo::Client - OpenID Connect Demo Client using OIDC::Lite

# DESCRIPTION

OpenID Connect Demo Client using OIDC::Lite

# SYNOPSIS

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

# AUTHOR

Ryo Ito <ritou.06@gmail.com>

# COPYRIGHT AND LICENSE

Copyright (C) 2013 by Ryo Ito

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.
