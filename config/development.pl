use File::Spec;
use File::Basename qw(dirname);
my $basedir = File::Spec->rel2abs(File::Spec->catdir(dirname(__FILE__), '..'));
my $dbpath = File::Spec->catfile($basedir, 'db', 'oidc_lite_demo_client_development.db');
+{
    'DBI' => [
        "dbi:SQLite:dbname=$dbpath", '', '',
        +{
            sqlite_unicode => 1,
        }
    ],
    'Credentials' => {
        'Google' => {
            'client_id' => q{aaa},
            'client_secret' => q{bbb},
            'redirect_uri' => q{http://localhost:5000/google/callback},
            'scope' => q{openid email profile},
        },
    },
};
