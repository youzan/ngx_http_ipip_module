PATH := /usr/local/nginx/sbin:$(PATH)
test:
	@WORKDIR=$(shell pwd) /usr/bin/prove

.PHONY: test
