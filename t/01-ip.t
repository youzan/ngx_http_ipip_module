use Test::Nginx::Socket 'no_plan';

my $workdir = $ENV{WORKDIR};

our $http_config;

if (-f '$workdir/fixtures/fake_ip.datx') {
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


repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: test 8.8.8.8 should ok
--- http_config eval: $::http_config
--- config
location /ip {
    ipip on;
}

--- request
GET /ip?ip=8.8.8.8

--- response_body_like
.*GOOGLE.*

--- error_code: 200


=== TEST 2: test 8.8.8 should ok
--- http_config eval: $::http_config
--- config
location = /ip {
    ipip on;
}

--- request
GET /ip?ip=8.8.8

--- response_body eval
'{"ret": "ok", "data": []}'
--- error_code: 200
