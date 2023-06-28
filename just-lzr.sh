echo "112.80.248.75:443" | sudo ./lzr --handshakes tls -sendSYNs -sourceIP 192.168.0.167 -sendInterface eno1 -gatewayMac c8:ea:f8:e0:86:de -f lzr_results.json
