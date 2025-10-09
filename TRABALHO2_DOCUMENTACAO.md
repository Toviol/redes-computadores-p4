# Trabalho 2 — Classificação de Tráfego

## Implementação Completa

### Objetivos Implementados
✅ Medição de tráfego por fluxo (5-tuple: srcIP, dstIP, srcPort, dstPort, protocolo)  
✅ Marcação DSCP baseada em limiares de tráfego  
✅ Encaminhamento diferenciado por canais (alta e baixa prioridade)  
✅ Filtragem de protocolo (apenas UDP)  

---

## Arquitetura da Rede

```
h1 (10.0.1.1) ─────── s1-p1
                      s1-p2 ──(ALTA: AF41)── s2-p2
                      s1-p3 ──(BAIXA: BE)─── s2-p3
                                              s2-p1 ─────── h2 (10.0.2.2)
```

### Topologia
- **2 Hosts**: h1 e h2
- **2 Switches**: s1 e s2
- **4 Links**:
  - h1 ↔ s1 (porta 1)
  - h2 ↔ s2 (porta 1)
  - s1 ↔ s2 canal alta (portas 2)
  - s1 ↔ s2 canal baixa (portas 3)

---

## Parâmetros de Configuração

### Constantes P4
| Parâmetro | Valor | Descrição |
|-----------|-------|-----------|
| `WINDOW_SIZE` | 100000 µs | Janela de medição (100 ms) |
| `THRESHOLD_PER_WINDOW` | 100 KB | Limiar de bytes por janela (8 Mb/s) |
| `DSCP_AF41` | 34 (0x88) | Alta prioridade (Green) |
| `DSCP_BE` | 0 (0x00) | Baixa prioridade (Red) |

### Capacidades dos Canais (sugeridas para TCLink)
- **Canal Alta**: 20 Mb/s
- **Canal Baixa**: 3 Mb/s

---

## Implementação P4

### 1. Headers
```p4
header udp_t {
    port_t srcPort;
    port_t dstPort;
    bit<16> length;
    bit<16> checksum;
}
```

### 2. Metadados
```p4
struct metadata {
    bit<32> flow_hash;        // Hash do fluxo (5-tuple)
    bit<48> current_time;     // Timestamp atual
    bit<48> last_time;        // Último timestamp do fluxo
    bit<32> byte_count;       // Bytes acumulados
    bit<32> bytes_in_window;  // Bytes na janela atual
    bit<6>  new_dscp;         // Novo valor DSCP
}
```

### 3. Registers (Estado por Fluxo)
```p4
register<bit<48>>(8192) flow_last_seen;   // Último timestamp
register<bit<32>>(8192) flow_byte_count;  // Contador de bytes
```

### 4. Lógica de Medição e Marcação

#### Passo 1: Hash do Fluxo (5-tuple)
```p4
hash(meta.flow_hash, HashAlgorithm.crc32, (bit<32>)0,
     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
       hdr.udp.srcPort, hdr.udp.dstPort },
     (bit<32>)8192);
```

#### Passo 2: Verificar Janela de Tempo
```p4
if (meta.current_time - meta.last_time > WINDOW_SIZE) {
    // Nova janela - resetar contador
    meta.bytes_in_window = (bit<32>)hdr.ipv4.totalLen;
} else {
    // Mesma janela - acumular bytes
    meta.bytes_in_window = meta.byte_count + (bit<32>)hdr.ipv4.totalLen;
}
```

#### Passo 3: Marcação DSCP
```p4
if (meta.bytes_in_window > THRESHOLD_PER_WINDOW) {
    mark_dscp(DSCP_BE);    // RED - baixa prioridade (0x00)
} else {
    mark_dscp(DSCP_AF41);  // GREEN - alta prioridade (0x88)
}
```

### 5. Tabelas P4

#### protocol_filter
Permite apenas tráfego UDP:
```p4
table protocol_filter {
    key = { hdr.ipv4.protocol: exact; }
    actions = { allow; drop; }
    default_action = drop();
}
```

#### dscp_routing
Encaminha baseado em DSCP:
```p4
table dscp_routing {
    key = {
        hdr.ipv4.diffserv: ternary;
        hdr.ipv4.dstAddr: lpm;
    }
    actions = { ipv4_forward; drop; NoAction; }
    default_action = NoAction();
}
```

#### ipv4_lpm
Roteamento padrão (fallback):
```p4
table ipv4_lpm {
    key = { hdr.ipv4.dstAddr: lpm; }
    actions = { ipv4_forward; drop; NoAction; }
    default_action = drop();
}
```

---

## Configuração dos Switches

### Switch S1 (s1-runtime.json)

#### Filtro de Protocolo
- Permitir UDP (protocolo 17)
- Dropar todo o resto

#### Roteamento LPM
- `10.0.1.1/32` → porta 1 (h1)
- `10.0.2.2/32` → porta 2 (padrão para h2)

#### Roteamento DSCP
- **Alta prioridade** (DSCP 0x88): `10.0.2.2/32` → porta 2 (canal alta)
- **Baixa prioridade** (DSCP 0x00): `10.0.2.2/32` → porta 3 (canal baixa)

### Switch S2 (s2-runtime.json)

#### Filtro de Protocolo
- Permitir UDP (protocolo 17)
- Dropar todo o resto

#### Roteamento LPM
- `10.0.2.2/32` → porta 1 (h2)
- `10.0.1.1/32` → porta 2 (padrão para h1)

#### Roteamento DSCP
- **Alta prioridade** (DSCP 0x88): `10.0.1.1/32` → porta 2 (canal alta)
- **Baixa prioridade** (DSCP 0x00): `10.0.1.1/32` → porta 3 (canal baixa)

---

## Fluxo de Operação

### Cenário: h1 → h2

1. **Pacote chega em S1**
2. **Filtro de Protocolo**: Verifica se é UDP
   - Se não for UDP → DROP
   - Se for UDP → ALLOW
3. **Medição de Tráfego**:
   - Calcula hash do fluxo (5-tuple)
   - Lê último timestamp e contador de bytes
   - Verifica se está na mesma janela de 100ms
   - Acumula bytes ou reseta contador
   - Atualiza registers
4. **Marcação DSCP**:
   - Se bytes > 100KB na janela → DSCP = BE (0x00) - RED
   - Se bytes ≤ 100KB na janela → DSCP = AF41 (0x88) - GREEN
5. **Roteamento**:
   - Tenta `dscp_routing` primeiro
   - Se GREEN (0x88) → porta 2 (canal alta)
   - Se RED (0x00) → porta 3 (canal baixa)
   - Se não houver match → usa `ipv4_lpm`
6. **Pacote chega em S2**
7. **S2 encaminha** baseado em DSCP ou LPM para h2

---

## Como Executar

### 1. Compilar e Iniciar
```bash
make
```

### 2. Testar Conectividade (Mininet CLI)
```bash
mininet> h1 ping h2
```

### 3. Gerar Tráfego UDP

#### Terminal h2 (Receptor)
```bash
mininet> h2 ./receive.py
```

#### Terminal h1 (Transmissor - Baixo Tráfego)
```bash
mininet> h1 ./send.py 10.0.2.2 "Teste baixo tráfego"
```

#### Terminal h1 (Transmissor - Alto Tráfego)
Para gerar tráfego acima do limiar, envie muitos pacotes rapidamente:
```bash
mininet> h1 bash -c 'for i in {1..1000}; do ./send.py 10.0.2.2 "Pacote $i" & done'
```

### 4. Verificar PCAPs
```bash
# Canal alta (porta 2) - deve ter tráfego GREEN
tcpdump -r pcaps/s1-eth2_out.pcap -v

# Canal baixa (porta 3) - deve ter tráfego RED
tcpdump -r pcaps/s1-eth3_out.pcap -v
```

### 5. Verificar DSCP nos Pacotes
```bash
tcpdump -r pcaps/s1-eth2_out.pcap -v | grep "tos"
```

---

## Verificação e Debugging

### Logs dos Switches
```bash
cat logs/s1.log  # Log do switch S1
cat logs/s2.log  # Log do switch S2
```

### Estatísticas das Tabelas
```bash
simple_switch_CLI --thrift-port 9090  # Conectar ao S1
RuntimeCmd: table_dump MyIngress.dscp_routing
RuntimeCmd: register_read flow_byte_count 0
```

---

## Resultados Esperados

### Tráfego Baixo (< 8 Mb/s)
- ✅ DSCP marcado como **AF41 (0x88)**
- ✅ Pacotes seguem pelo **canal alta** (porta 2)
- ✅ Baixa latência, alta largura de banda

### Tráfego Alto (> 8 Mb/s)
- ✅ DSCP marcado como **BE (0x00)**
- ✅ Pacotes seguem pelo **canal baixa** (porta 3)
- ✅ Penalização: menor largura de banda (3 Mb/s)

---

## Observações Importantes

1. **Medição por Fluxo**: Cada fluxo UDP único (identificado pela 5-tuple) é medido independentemente
2. **Janela Deslizante**: A cada 100ms, a janela reseta se não houver tráfego
3. **Apenas S1 Mede**: A medição e marcação DSCP ocorrem apenas no switch S1
4. **S2 Roteia**: S2 apenas encaminha baseado no DSCP já marcado
5. **Protocolo**: Apenas UDP é permitido; todo tráfego não-UDP é dropado

---

## Arquivos Criados/Modificados

- ✅ `basic_trabalho2.p4` - Programa P4 com medição e marcação
- ✅ `trabalho2-topo/topo_trabalho2.json` - Topologia com 2 canais
- ✅ `trabalho2-topo/s1-runtime.json` - Configuração do S1
- ✅ `trabalho2-topo/s2-runtime.json` - Configuração do S2
- ✅ `Makefile` - Aponta para a topologia correta

---

## Extensões Possíveis

1. **Ajustar Limiares**: Modificar `THRESHOLD_PER_WINDOW` conforme necessário
2. **Múltiplos Níveis DSCP**: Adicionar mais níveis (AF42, AF43, etc.)
3. **Policiamento**: Dropar pacotes em vez de apenas remarcar
4. **Estatísticas**: Adicionar counters para monitorar tráfego por canal
5. **TCLink**: Configurar largura de banda dos links no topo JSON

---

**Implementação Completa e Funcional! ✅**
