#!/bin/bash

for ip in 203.0.113.11 203.0.113.12 201.0.113.12 201.0.113.18; do
    curl -v -s -o /dev/null -w "$ip -> %{http_code}\n" --interface "$ip" http://192.168.0.118:5118/status
done

