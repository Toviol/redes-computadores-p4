# SPDX-License-Identifier: Apache-2.0
BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = trabalho2-topo/topo_trabalho2.json

include ../../utils/Makefile

# Remove the -j parameter since it's specified in the topology file
# run: build
# 	sudo PATH=$(PATH) PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 ../../utils/run_exercise.py -t $(TOPO) -b $(BMV2_SWITCH_EXE)

# build: dirs
# 	p4c-bm2-ss --p4v 16 --p4runtime-files build/s1_trabalho2.p4.p4info.txtpb -o build/s1_trabalho2.json s1_trabalho2.p4
# 	p4c-bm2-ss --p4v 16 --p4runtime-files build/s2_trabalho2.p4.p4info.txtpb -o build/s2_trabalho2.json s2_trabalho2.p4

# dirs:
# 	mkdir -p build pcaps logs

# stop:
# 	sudo mn -c

# clean: stop
# 	-rm -f *.pcap
# 	-rm -rf build pcaps logs