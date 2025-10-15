# Link de 2 Mbps
s1 tc qdisc add dev s1-eth2 root tbf rate 2mbit burst 10kb latency 50ms
s2 tc qdisc add dev s2-eth2 root tbf rate 2mbit burst 10kb latency 50ms

# Link de 300 kbps
s1 tc qdisc add dev s1-eth3 root tbf rate 300kbit burst 10kb latency 50ms
s2 tc qdisc add dev s2-eth3 root tbf rate 300kbit burst 10kb latency 50ms

# fora do mininet esses do wireshark
# abrir 3 wireshark e ver a porta 2 e porta 3 do s1 e h2
sudo wireshark &
sudo wireshark &
sudo wireshark

h1 sudo python3 send_two_flows.py --dst 10.0.2.2 --sport1 5000 --dport1 5001 --size1 500 --rate1 0.5 --sport2 6000 --dport2 6001 --size2 1200 --rate2 1.2 --count 50




# alternativo com tcpdump

# No Mininet:
mininet> h2 sudo tcpdump -i h2-eth0 -vv -n udp port 5001 &
mininet> h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 5000 --dport 5001 --count 50 --size 800 --rate 5