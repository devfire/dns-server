#!/usr/bin/env bash
for i in {1..100}; do
	DNS=$(echo "$(tr -dc 'a-z' < /dev/urandom | head -c $((RANDOM%6+5))).$(tr -dc 'a-z' < /dev/urandom | head -c $((RANDOM%6+5))).$(tr -dc 'a-z' < /dev/urandom | head -c 2)")
	dig @127.0.0.1 -p 2053 $DNS &
done
