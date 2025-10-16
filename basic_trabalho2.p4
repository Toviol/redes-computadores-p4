// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_UDP = 17;

// DSCP values
const bit<6> DSCP_AF41 = 34;  // Alta prioridade (Green)
const bit<6> DSCP_BE = 0;     // Baixa prioridade (Red)

// Traffic monitoring parameters
const bit<48> WINDOW_SIZE = 100000;  // 100ms em microsegundos
const bit<48> PENALTY_TIME = 1000000; // 10 janelas = 1 segundo (tempo para poder voltar para GREEN)
const bit<32> THRESHOLD_PER_WINDOW = 1000; // 800 Kbps * 0.1s = 10.000 bytes em 100ms
// Explicação: 800 Kbps = 800.000 bits/s = 100.000 bytes/s
// Em 100ms (0.1s): 100.000 bytes/s * 0.1s = 10.000 bytes

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    port_t srcPort;
    port_t dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<32> flow_hash;
    bit<48> current_time;
    bit<48> window_start;
    bit<48> last_violation;
    bit<48> time_in_window;
    bit<32> byte_count;
    bit<32> bytes_in_window;
    bit<6>  new_dscp;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // Registers para medição de tráfego por fluxo
    register<bit<48>>(8192) flow_window_start;   // Timestamp do início da janela atual
    register<bit<32>>(8192) flow_byte_count;     // Contador de bytes na janela atual
    register<bit<48>>(8192) flow_last_violation; // Timestamp da última violação (para penalty)
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action allow() {
        // Permite o pacote continuar
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action mark_dscp(bit<6> dscp_value) {
        hdr.ipv4.diffserv = ((bit<8>)dscp_value) << 2;
    }

    table protocol_filter {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            allow;
            drop;
        }
        size = 256;
        default_action = drop();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table dscp_routing {
        key = {
            hdr.ipv4.diffserv: ternary;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (protocol_filter.apply().hit) {
                
                // Medição de tráfego apenas no switch S1
                if (hdr.udp.isValid()) {
                    // Calcular hash do fluxo (5-tuple)
                    hash(meta.flow_hash,
                         HashAlgorithm.crc32,
                         (bit<32>)0,
                         { hdr.ipv4.srcAddr,
                           hdr.ipv4.dstAddr,
                           hdr.ipv4.protocol,
                           hdr.udp.srcPort,
                           hdr.udp.dstPort },
                         (bit<32>)8192);
                    
                    // Obter timestamp atual (em microsegundos)
                    meta.current_time = standard_metadata.ingress_global_timestamp;
                    
                    // Ler estado do fluxo
                    flow_window_start.read(meta.window_start, meta.flow_hash);
                    flow_byte_count.read(meta.byte_count, meta.flow_hash);
                    flow_last_violation.read(meta.last_violation, meta.flow_hash);
                    
                    // Calcular tempo decorrido desde o início da janela
                    meta.time_in_window = meta.current_time - meta.window_start;
                    
                    // Verificar se a janela atual expirou (passou 100ms)
                    if (meta.window_start == 0 || meta.time_in_window > WINDOW_SIZE) {
                        // Iniciar nova janela
                        meta.window_start = meta.current_time;
                        meta.bytes_in_window = (bit<32>)hdr.ipv4.totalLen;
                    } else {
                        // Dentro da janela atual - acumular bytes
                        meta.bytes_in_window = meta.byte_count + (bit<32>)hdr.ipv4.totalLen;
                    }
                    
                    // Verificar se excedeu o limiar nesta janela
                    if (meta.bytes_in_window > THRESHOLD_PER_WINDOW) {
                        // Violação! Marcar timestamp da violação
                        meta.last_violation = meta.current_time;
                        flow_last_violation.write(meta.flow_hash, meta.last_violation);
                    }
                    
                    // Atualizar registers da janela
                    flow_window_start.write(meta.flow_hash, meta.window_start);
                    flow_byte_count.write(meta.flow_hash, meta.bytes_in_window);
                    
                    // Decidir DSCP: Uma vez em RED, só volta para GREEN após PENALTY_TIME
                    // sem violações (10 janelas = 1 segundo)
                    if (meta.last_violation == 0) {
                        // Nunca violou - GREEN
                        meta.new_dscp = DSCP_AF41; // Green - Alta prioridade
                    } else if (meta.current_time - meta.last_violation > PENALTY_TIME) {
                        // Passou tempo suficiente sem violar - pode voltar para GREEN
                        meta.new_dscp = DSCP_AF41; // Green - Alta prioridade
                    } else {
                        // Ainda em período de penalidade - RED
                        meta.new_dscp = DSCP_BE; // Red - Baixa prioridade
                    }
                    
                    mark_dscp(meta.new_dscp);
                }
                
                // Tentar roteamento baseado em DSCP primeiro
                if (!dscp_routing.apply().hit) {
                    // Fallback para roteamento normal se não houver regra DSCP
                    ipv4_lpm.apply();
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
