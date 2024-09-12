#!/bin/bash
 
ROOT="$(dirname "$0")"
source $ROOT/sources/extra.sh

function show_help () 
{ 
  c_print "White" "------------------------------------------------------------"
 	c_print "White" "This script extract features from raw PCAP files. 
  \nIn particular, it runs Zeek and several tshark processes to 
  \nget different levels of granularity"
  c_print "White" "------------------------------------------------------------"
 	c_print "Bold" "Example: sudo ./extract_features -i <INPUT.PCAP> [-o OUTPUT_DIR] [-s SSLKEYLOGFILE]"
  c_print "Bold" "\t-i <INPUT>: The pcap file to extract features from"
  c_print "Bold" "\t[-o <OUTPUT_DIR>]: Output directory (Default: ${ROOT}/output_dir)"
  c_print "Bold" "\t[-s <SSLKEYLOGFILE>]: In case you have SSLKEYLOGFILE, tshark can decrypt payloads (Default: None)"
 	exit $1
}

function run_zeek ()
{
  pcap_path=$1
  

  return $pid
}

### GLOBAL VARS
TSHARK_FIELDS="-e frame.number -e _ws.col.Time -e frame.time_delta -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info"
INPUT=""
OUTPUT_DIR="${ROOT}/output_dir"
SSLKEYLOGFILE=""

while getopts "h?i:o:s:" opt
do
  case "$opt" in
    h|\?)
      show_help
      ;;
    i)
      INPUT=$OPTARG
      ;;
    o)
      OUTPUT_DIR=$OPTARG
      ;;  
    s)
      SSLKEYLOGFILE=$OPTARG
      ;;  
    *)
      show_help
      ;;
esac
done

if [[ -z $INPUT ]]
then
  c_print "Red" "No INPUT.PCAP was provided!"
  show_help
fi

c_print "White" "Creating output dir ${OUTPUT_DIR}" 1
mkdir -p $OUTPUT_DIR
retval=$?
check_retval $retval

c_print "White" "Extrating features from ${INPUT} to ${OUTPUT_DIR}..."


pcap_name=$(basename "$INPUT")

##############
#### ZEEK ####
##############
zeek_dir="${OUTPUT_DIR}/${pcap_name}.zeek/"
c_print "Blue" "[Zeek.thread] Creating Zeek output dir ${zeek_dir}" 1
mkdir -p $zeek_dir
retval=$?
check_retval $retval

# zeek_cmd="/opt/zeek/bin/zeek -C -r ${pcap_path} Log::default_logdir=${zeek_dir}"
# $zeek_cmd 
zeek_start=$(date +%s)
/opt/zeek/bin/zeek -C -r "$INPUT" Log::default_logdir="$zeek_dir" &
zeek_pid=$!
c_print "Blue" "[Zeek.thread] Zeek PID is ${zeek_pid}"


################
#### TSHARK ####
# PACKET_LEVEL #
################
tshark_main_cmd="tshark -r ${INPUT} "
csv_filename="${OUTPUT_DIR}/${pcap_name}"

if [[ ! -z $SSLKEYLOGFILE ]]
then
  tshark_main_cmd=$(echo "${tshark_main_cmd} -o tls.keylog_file:{SSLKEYLOGFILE}")
fi

c_print "Orange" "[TSHARK.PACKET_LEVEL thread] Gathering packet level data" 
tshark_packet_level_cmd="${tshark_main_cmd} -T fields ${TSHARK_FIELDS} -E header=y -E separator=; -E quote=d -E occurrence=f" 
tshark_packet_level_cmd_start=$(date +%s)
$tshark_packet_level_cmd > ${csv_filename}.PACKET_LEVEL.csv &
tshark_packet_level_cmd_pid=$!
c_print "Orange" "[TSHARK.PACKET_LEVEL thread] PID is ${tshark_packet_level_cmd_pid}"

#### TSHARK #####
# FLOW_LEVEL_L3 #
#################
c_print "Purple" "[TSHARK.FLOW_LEVEL_L3 thread] Gathering Layer-3 flow level data" 
echo "src_ip;dst_ip;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration" > ${csv_filename}.FLOW_LEVEL_L3.csv
tshark_flow_l3_cmd="${tshark_main_cmd} -q -z conv,ip" 
tshark_flow_l3_cmd_start=$(date +%s)
#run the command
$tshark_flow_l3_cmd |grep -v ==|grep -v IPv4|grep -v Filter|grep -v "|" | awk '{print $1";"$3";"$4";"$5";"$6";"$7";"$8";"$9";"$10";"$11";"$12";"$13";"$14}' >> ${csv_filename}.FLOW_LEVEL_L3.csv &
#get the PID
tshark_flow_l3_cmd_pid=$!
c_print "Purple" "[TSHARK.FLOW_LEVEL_L3 thread] PID is ${tshark_flow_l3_cmd_pid}"

#### TSHARK #########
# FLOW_LEVEL_L4_TCP #
#####################
c_print "Cyan" "[TSHARK.FLOW_LEVEL_L4_TCP thread] Gathering Layer-4 TCP flow level data" 
echo "src_ip;sport;dst_ip;dport;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration" > ${csv_filename}.FLOW_LEVEL_L4_TCP.csv 
tshark_flow_l4_tcp_cmd="${tshark_main_cmd} -q -z conv,tcp"
tshark_flow_l4_tcp_cmd_start=$(date +%s)
#run the command
$tshark_flow_l4_tcp_cmd |grep -v ==|grep -v TCP | grep -v Filter|grep -v "|" |awk '{split($1,a,":"); split($3,b,":"); print a[1]";"a[2]";"b[1]";"b[2]";"$4";"$5";"$6";"$7";"$8";"$9";"$10";"$11";"$12";"$13";"$14}'>> ${csv_filename}.FLOW_LEVEL_L4_TCP.csv &
#get the PID
tshark_flow_l4_tcp_cmd_pid=$!
c_print "Cyan" "[TSHARK.FLOW_LEVEL_L4_TCP thread] PID is ${tshark_flow_l4_tcp_cmd_pid}"


#### TSHARK #########
# FLOW_LEVEL_L4_UDP #
#####################
c_print "Yellow" "[TSHARK.FLOW_LEVEL_L4_UDP thread] Gathering Layer-4 UDP flow level data" 
echo "src_ip;sport;dst_ip;dport;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration" > ${csv_filename}.FLOW_LEVEL_L4_UDP.csv
tshark_flow_l4_udp_cmd="${tshark_main_cmd} -q -z conv,udp"
tshark_flow_l4_udp_cmd_start=$(date +%s)
#run the command
$tshark_flow_l4_udp_cmd |grep -v ==|grep -v UDP | grep -v Filter|grep -v "|" |awk '{split($1,a,":"); split($3,b,":"); print a[1]";"a[2]";"b[1]";"b[2]";"$4";"$5";"$6";"$7";"$8";"$9";"$10";"$11";"$12";"$13";"$14}'>> ${csv_filename}.FLOW_LEVEL_L4_UDP.csv &
#get the PID
tshark_flow_l4_udp_cmd_pid=$!
c_print "Yellow" "[TSHARK.FLOW_LEVEL_L4_UDP thread] PID is ${tshark_flow_l4_udp_cmd_pid}"


#### TSHARK #########
# EXTRACT ENDPOINTS #
#####################
c_print "Green" "[TSHARK.ENDPOINTS thread] Gathering Endpoint level data" 
echo "ip;all_pkts;all_bytes;sent_pkts;sent_bytes;recv_pkts;recv_bytes" > ${csv_filename}.EXTRACT_ENDPOINTS.csv
tshark_endpoint_cmd="${tshark_main_cmd} -q -z endpoints,ipv4"
tshark_endoint_cmd_start=$(date +%s)
#run the command
$tshark_endpoint_cmd |grep -v ==|grep -v IPv4|grep -v Filter|grep -v "|" |awk '{print $1";"$2";"$3";"$4";"$5";"$6";"$7}' >> ${csv_filename}.EXTRACT_ENDPOINTS.csv &
#get the PID
tshark_endpoint_cmd_pid=$!
c_print "Green" "[TSHARK.ENDPOINTS thread] PID is ${tshark_endpoint_cmd_pid}"


##########################################
## WAITING FOR THE THREADS TO FINISH AH ##
##########################################
wait $zeek_pid
zeek_stop=$(date +%s)
duration=$(( $zeek_stop - $zeek_start ))
c_print "Blue" "[Zeek.thread] FINISHED"
time=$(format_time $duration)
c_print "Blue" "[Zeek.thread] Time: ${time}"

wait $tshark_packet_level_cmd_pid
tshark_packet_level_cmd_stop=$(date +%s)
duration=$(( $tshark_packet_level_cmd_stop - $tshark_packet_level_cmd_start ))
c_print "Orange" "[TSHARK.PACKET_LEVEL thread] FINISHED"
time=$(format_time $duration)
c_print "Orange" "[TSHARK.PACKET_LEVEL thread] Time: ${time}"

wait $tshark_flow_l3_cmd_pid
tshark_flow_l3_cmd_stop=$(date +%s)
duration=$(( $tshark_flow_l3_cmd_stop - $tshark_flow_l3_cmd_start ))
c_print "Purple" "[TSHARK.FLOW_LEVEL_L3 thread] FINISHED"
time=$(format_time $duration)
c_print "Purple" "[TSHARK.FLOW_LEVEL_L3 thread] Time: ${time}"


wait $tshark_flow_l4_tcp_cmd_pid
tshark_flow_l4_tcp_cmd_stop=$(date +%s)
duration=$(( $tshark_flow_l4_tcp_cmd_stop - $tshark_flow_l4_tcp_cmd_start ))
c_print "Cyan" "[TSHARK.FLOW_LEVEL_L4_TCP thread] FINISHED"
time=$(format_time $duration)
c_print "Cyan" "[TSHARK.FLOW_LEVEL_L4_TCP thread] Time: ${time}"


wait $tshark_flow_l4_udp_cmd_pid
tshark_flow_l4_udp_cmd_stop=$(date +%s)
duration=$(( $tshark_flow_l4_udp_cmd_stop - $tshark_flow_l4_udp_cmd_start ))
c_print "Yellow" "[TSHARK.FLOW_LEVEL_L4_UDP thread] FINISHED"
time=$(format_time $duration)
c_print "Yellow" "[TSHARK.FLOW_LEVEL_L4_UDP thread] Time: ${time}"

wait $tshark_endpoint_cmd_pid
tshark_endoint_cmd_stop=$(date +%s)
duration=$(( $tshark_endoint_cmd_stop - $tshark_endoint_cmd_start ))
c_print "Green" "[TSHARK.ENDPOINTS thread] FINISHED"
time=$(format_time $duration)
c_print "Green" "[TSHARK.ENDPOINTS thread] Time: ${time}"


c_print "BGreen" " ---------- ALL PROCESS FINISHED ------------ \n"