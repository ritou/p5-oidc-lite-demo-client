use File::Spec;
use File::Basename qw(dirname);
my $basedir = File::Spec->rel2abs(File::Spec->catdir(dirname(__FILE__), '..'));
my $dbpath = File::Spec->catfile($basedir, 'db', 'test.db');
+{
    'DBI' => [
        "dbi:SQLite:dbname=$dbpath", '', '',
        +{
            sqlite_unicode => 1,
        }
    ],
    'Credentials' => {
        'Google' => {
            'client_id' => q{your app's client_id},
            'client_secret' => q{your app's client_secret},
            'redirect_uri' => q{http://localhost:5000/callback},
            'scope' => q{openid email},
        },
    },
};
