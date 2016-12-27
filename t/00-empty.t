use Test::Nginx::Socket 'no_plan';

my $workdir = $ENV{WORKDIR};

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: test empty ip datx should ok
--- config
location /ip {
    ipip on;
}

--- request
GET /ip?ip=8.8.8.8

--- response_body eval
'{"ret": "ok", "data": []}'

--- error_code: 200


=== TEST 2: test empty phone txt should ok
--- config
location = /phone {
    ipip on;
}

--- request
GET /phone?phone=13000000000

--- response_body eval
'{"ret": "ok", "data": []}'
--- error_code: 200
