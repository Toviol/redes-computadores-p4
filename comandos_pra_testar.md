# No Mininet:
mininet> h2 sudo tcpdump -i h2-eth0 -vv -n udp port 5001 &
mininet> h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 5000 --dport 5001 --count 50 --size 800 --rate 5





# Fora do Mininet, em um terminal novo:
sudo wireshark &

# No Wireshark:
# 1. Capture > Options
# 2. Selecione a interface: h2-eth0 (ou s1-eth2 para ver canal ALTA)
# 3. Filter: udp
# 4. Start

# No Mininet:
mininet> h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 5000 --dport 5001 --count 50 --size 1200 --rate 10
mininet> h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 6000 --dport 6001 --count 50 --size 800 --rate 5



# Fora do Mininet, em 2 terminais:

# Terminal 1 - Monitorar canal ALTA (porta 2 do s1):
sudo tcpdump -i s1-eth2 -n udp

# Terminal 2 - Monitorar canal BAIXA (porta 3 do s1):
sudo tcpdump -i s1-eth3 -n udp

# No Mininet:
# Enviar tráfego BAIXO (deve ir pelo canal ALTA):
h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 5000 --dport 5001 --count 50 --size 800 --rate 5

# Enviar tráfego ALTO (deve ir pelo canal BAIXA):
h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 6000 --dport 6001 --count 100 --size 1400 --rate 15






# 1. Inicie o Mininet:
make run

# 2. Fora do Mininet, abra Wireshark:
sudo wireshark &
# Selecione interface: h2-eth0
# Filtro: udp
# Start

# 3. No Mininet, envie tráfego variado:

# Tráfego BAIXO (esperado: DSCP=34, canal ALTA):
h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 5000 --dport 5001 --count 50 --size 800 --rate 5

# Aguarde 2 segundos...

# Tráfego ALTO (esperado: DSCP=0, canal BAIXA):
h1 sudo python3 send_udp.py --dst 10.0.2.2 --sport 6000 --dport 6001 --count 100 --size 1400 --rate 12

# 4. No Wireshark, veja os pacotes:
# - Porta 5001: DSCP = AF41 (34) 🟢
# - Porta 6001: DSCP = Default (0) 🔴