#!/bin/bash

PCAP=$1
INTERVAL=$2 # seconds

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <pcap file> <interval>"
    exit 1
fi

if [ -z "$INTERVAL" ]; then
    echo "Usage: $0 <pcap file> <interval>"
    exit 1
fi

echo "expert info"
tshark -r ${PCAP} -q -z expert


# tcp.analysis.retransmission
# tcp.analysis.fast_retransmission
# tcp.analysis.lost_segment
# tcp.analysis.duplicate_ack
# 计算丢包率
echo "tcp loss rate: packets/${INTERVAL}s "
tshark -r ${PCAP} -q \
-z io,stat,${INTERVAL},"COUNT(tcp.analysis.retransmission) tcp.analysis.retransmission","COUNT(tcp.analysis.fast_retransmission) tcp.analysis.fast_retransmission","COUNT(tcp.analysis.duplicate_ack) tcp.analysis.duplicate_ack","COUNT(tcp.analysis.lost_segment) tcp.analysis.lost_segment"

# 计算 tcp RTT
echo "tcp rtt"
tshark -o tcp.desegment_tcp_streams:TRUE -n \
-q -r  ${PCAP}  -z \
io,stat,99999999,"AVG(tcp.analysis.ack_rtt)tcp.analysis.ack_rtt"

tshark -r ${PCAP} -q -z \
io,stat,${INTERVAL},"MIN(tcp.analysis.ack_rtt)tcp.analysis.ack_rtt",\
"MAX(tcp.analysis.ack_rtt)tcp.analysis.ack_rtt",\
"AVG(tcp.analysis.ack_rtt)tcp.analysis.ack_rtt"

