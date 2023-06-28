sudo zmap $1 --target-port=80 --output-filter="success = 1 && repeat = 0" -f "saddr,daddr,sport,dport,seqnum,acknum,window" -O json --source-ip=192.168.0.167  | \
sudo ./lzr --handshakes ssh -sendInterface eno1 -gatewayMac c8:ea:f8:e0:86:de
