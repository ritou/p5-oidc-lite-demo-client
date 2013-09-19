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
        'Sample' => {
            'authorization_endpoint' => 'http://localhost:5001/authorize',
            'token_endpoint' => 'http://localhost:5001/token',
            'userinfo_endpoint' => 'http://localhost:5001/userinfo',
            'client_id' => q{sample_client_id},
            'client_secret' => q{sample_client_secret},
            'redirect_uri' => q{http://localhost:5000/sample/callback},
            'scope' => q{openid email profile phone address},
        },
        'IDIT' => {
            'authorization_endpoint' => 'https://oidp.pf-demo-jp.com/as/authorization.oauth2',
            'token_endpoint' => 'https://oidp.pf-demo-jp.com/as/token.oauth2',
            'userinfo_endpoint' => 'https://oidp.pf-demo-jp.com/idp/userinfo.openid',
            'client_id' => q{your app's client_id},
            'client_secret' => q{your app's client_secret},
            'redirect_uri' => q{http://localhost:5000/idit2013/callback},
            'scope' => q{openid email profile},
        },
    },
};
