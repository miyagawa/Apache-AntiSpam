use strict;
use Test;
BEGIN { plan tests => 3 }

use Apache::AntiSpam;
ok(1);

use mod_perl;
ok($mod_perl::VERSION >= 1.21);

eval { require Apache::Filter; };
ok($@ || $Apache::Filter::VERSION >= 1.013);

# keep warnings silent 
$Apache::Filter::VERSION += 0;

    
