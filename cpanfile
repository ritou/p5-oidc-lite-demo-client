requires 'Amon2', '3.87';
requires 'Text::Xslate', '1.6001';
requires 'Amon2::DBI'                     , '0.30';
requires 'DBD::SQLite'                    , '1.33';
requires 'HTML::FillInForm::Lite'         , '1.11';
requires 'JSON::XS'                       , '0';
requires 'Module::Functions'              , '2';
requires 'Plack::Middleware::ReverseProxy', '0.09';
requires 'Plack::Middleware::Session'     , '0';
requires 'Plack::Session'                 , '0.14';
requires 'Test::WWW::Mechanize::PSGI'     , '0';
requires 'Time::Piece'                    , '1.20';
requires 'Teng'                           , '0.19';

requires 'OAuth::Lite2'                   , '0.05';
requires 'OIDC::Lite'                     , '0.03';
requires 'Crypt::OpenSSL::Random'         , '0';
requires 'Crypt::OpenSSL::CA'             , '0';

on 'configure' => sub {
   requires 'Module::Build', '0.38';
   requires 'Module::CPANfile', '0.9010';
};

on 'test' => sub {
    requires 'Test::More', '0.98';
};
