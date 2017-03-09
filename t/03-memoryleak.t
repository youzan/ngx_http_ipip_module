BEGIN {
    $ENV{TEST_NGINX_CHECK_LEAK} = 1;
}

use Test::Nginx::Socket 'no_plan';


my $workdir = $ENV{WORKDIR};

our $http_config;

if (-f '$workdir/fixtures/real_ip.datx') {
    $http_config = <<"_EOC_";
        ipip_ip_datx '$workdir/fixtures/real_ip.datx';
        ipip_phone_txt '$workdir/fixtures/real_phone.txt';
_EOC_

} else {
    $http_config = <<"_EOC_";
        ipip_ip_datx '$workdir/fixtures/fake_ip.datx';
        ipip_phone_txt '$workdir/fixtures/fake_phone.txt';
_EOC_
}

repeat_each(4096);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: test empty ip datx should do not leak memory
--- http_config eval: $::http_config
--- config
location /ip {
    ipip on;
}

--- request
GET /ip?ip=8.8.8.8

--- error_code: 200
