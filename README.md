[ipip]: https://www.ipip.net/

# ngx_http_ipip_module
[![Build](https://api.travis-ci.org/youzan/ngx_http_ipip_module.svg)](https://travis-ci.org/youzan/ngx_http_ipip_module) [![release](https://img.shields.io/github/release/youzan/ngx_http_ipip_module.svg)](https://github.com/youzan/ngx_http_ipip_module/releases)


ngx_http_ipip_module is an addon for nginx to [ipip]

Table of Contents
-----------------
* [How-To-Use](#how-to-use)
* [How-To-Autoupdate](#how-to-autoupdate)
* [Requirements](#requirements)
* [Direction](#direction)
* [Contributing](#contributing)
* [License](#license)


How-To-Use
----------------
Set the nginx config for ngx_http_ipip_module as the following:

```bash
http {
    ipip_ip_datx /xx/real_ip.datx;
    ipip_phone_txt /xx/real_phone.txt;

    server {
        listen 1999;

        location / {
                ipip on;
        }
    }
}
```

now you can get the ip info as the following:

```bash
[root@localhost ~]# curl "http://127.0.0.1:1999/ip?ip=8.8.8.8"
{
    "ret":  "ok",
    "data": ["GOOGLE", "GOOGLE", "", "google.com", "level3.com", "", "", "", "", "", "", "*", "*"]
}
```
or you can get the phone info as the following:

```bash
[root@localhost ~]# curl "http://127.0.0.1:1999/phone?phone=13000000101"
{
    "ret":  "ok",
    "data": ["北京", "北京", "中国联通网络"]
}
```

How-To-Autoupdate
----------------

According the check-version api of [ipip], we can check the ip and phone version automaticly. We're recommanded to use crontab to autoupdate as the following:

```bash
1 3 * * * xx flock -n /xx/ipip.lock /path/to/ngx_http_ipip_module/scripts/autoupdate.sh &> /data/logs/ipinfo.log
```

By the way, you must set the private data which is the token on [ipip] to the scripts/var file as the following:

```bash
export IPTOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaa
export PHONETOKEN=bbbbbbbbbbbbbbbbbbbbbbbbbbbb
export PATH=/opt/nginx/sbin:$PATH
```

Also you can rewrite the autoupdate.sh to suit for yourself. And the `fake_ip.datx` and `fake_phone.txt` are the fake file in order to run tests (we are recommanded to buy the service from ipip for getting the real file).

Requirements
------------

ngx_http_ipip_module requires the following to run:

 * [nginx](http://nginx.org/) or other version like [openresty](http://openresty.org/)、[tengine](http://tengine.taobao.org/)
 * [test-nginx](https://github.com/openresty/test-nginx) only for run tests
 * [ipip] ip datx and phone number txt file

Direction
------------

* ipip_ip_datx: sepcify the ip datx file
Syntax:     ipip_ip_datx /path/to/file
Default:    -
Context:    main

```bash
http {
    ipip_ip_datx /xx/real_ip.datx;
}
```

* ipip_phone_txt: sepcify the phone txt file
Syntax:     ipip_phone_txt /path/to/file
Default:    -
Context:    main

```bash
http {
    ipip_phone_txt /xx/real_phone.txt;
}
```

* ipip: enable the ngx_http_ipip_module
Syntax:     ipip on|false
Default:    -
Context:    loc

```bash
location / {
    ipip on;
}
```

Contributing
------------

To contribute to ngx_http_ipip_module, clone this repo locally and commit your code on a separate branch.


License
-----------
This module is licenced under the BSD license.

Copyright (C) 2016 by Yang Bingwu (detailyang) detailyang@gmail.com, YouZan Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
