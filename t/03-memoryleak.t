use Test::Nginx::Socket 'no_plan';

BEGIN {
    $ENV{TEST_NGINX_CHECK_LEAK} = 1;
}

my $workdir = $ENV{WORKDIR};

repeat_each(1024);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: test empty ip datx should do not leak memory
--- config
location /ip {
    ipip on;
}

--- request
GET /ip?ip=8.8.8.8

--- response_body eval
'{"ret": "ok", "data": []}'

--- error_code: 200
