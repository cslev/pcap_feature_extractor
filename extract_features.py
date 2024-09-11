#!/usr/bin/env python3
# coding: utf-8

import os
import multiprocessing
import subprocess
from termcolor import colored
import argparse
import datetime
import time
import sys #to flush stdout after every print otherwise thread's printout methods block each other
from enum import Enum #for enums


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

#################
# ARG PARSING
#################
parser = argparse.ArgumentParser(description="Feature Extraction usage")
parser.add_argument('-i', '--input', 
                    action="store", 
                    required=True, 
                    dest="PCAP",
                    help="The pcap file to extract features from")

parser.add_argument('-m', '--method', 
                    action="store", 
                    required=False, 
                    default="both",
                    dest="METHOD",
                    help="The methods to be used, possible values: 'both', 'tshark', 'zeek' (Default: both)")
parser.add_argument('-s', '--sslkeylogfile',
                    action="store", 
                    required=False, 
                    dest="SSLKEYLOGFILE",
                    default=None,
                    help=f"In case you have SSLKEYLOGFILE, tshark can decrypt payloads (Default: None")

parser.add_argument('-o', '--outputdir',
                    action="store", 
                    required=False, 
                    dest="OUTPUT_DIR",
                    default=f"{SCRIPT_DIR}/output_dir",
                    help=f"Output directory (Default: {SCRIPT_DIR}/output_dir)")


#################
# GLOBAL VARS
#################
# parsing args
args = parser.parse_args()
PCAP = args.PCAP
PCAP_NAME = os.path.basename(PCAP)
METHOD = args.METHOD
SSLKEYLOGFILE = args.SSLKEYLOGFILE
OUTPUT_DIR = args.OUTPUT_DIR
if(not os.path.exists(OUTPUT_DIR)):
  os.makedirs(OUTPUT_DIR)


LOGFILE=f"{SCRIPT_DIR}/extract_features.log"
LOG = open(LOGFILE, 'w')


# enum for tshark extraction levels
class TSHARK_EXTRACTIONS(Enum):
  PACKET_LEVEL = 1
  FLOW_LEVEL_L3 = 2
  FLOW_LEVEL_L4_TCP = 3
  FLOW_LEVEL_L4_UDP = 4
  EXTRACT_ENDPOINTS = 5

TSHARK_FIELDS = "-e frame.number -e _ws.col.Time -e frame.time_delta -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e frame.len -e _ws.col.Info"


##############
# FUNCTIONS 
##############
#we need this variable to avoid printing thread_name if we print in the same line
newline_used_last_time=True 
def log(msg, newline=True, highlight=None, attr=None, thread_name="[MAIN.thread] "):
  '''
  This function is only for logging into file and to stdout
  '''
  global LOG
  global newline_used_last_time

  ##############
  # TEXT COLORS
  # black, red, green, yellow, blue, magenta,cyan, white, 
  # light_grey, dark_grey, light_red, light_green, light_yellow, 
  # light_blue, light_magenta, light_cyan
  # ATTRIBUTES
  # bold, dark, underline, blink, reverse, concealed
  ##############
  colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
  # let's hash the thread name into the colors as buckets to get a random but 
  # consistent color every time
  hash_value = hash(thread_name)
  c = hash_value % len(colors)
  thread_color = colors[c]
  
  #print out thread name first without newline at the end
  if(newline_used_last_time):
    print(colored(f"{thread_name} ", thread_color, attrs=['bold']), end='')

  if(newline):
    newline_used_last_time=True
    if(attr is not None):
      print(colored(msg, highlight, attrs=[attr]))
    else:
      print(colored(msg, highlight))
    LOG.write(msg + "\n")
    LOG.flush()
  else:
    newline_used_last_time=False
    if(attr is not None):
      print(colored(msg, highlight, attrs=[attr]), end='')
    else:
      print(colored(msg, highlight), end='')
    LOG.write(msg)
    LOG.flush()
  #flush stdout in every case to avoid threads blocking stdout
  sys.stdout.flush()

def getDateFormat(timestamp):
  '''
  This simple function converts traditional UNIX timestamp to YMD_HMS format
  timestamp int - unix timestamp to be converted
  return String - the YMD_HMS format as a string
  '''
  return datetime.datetime.\
    fromtimestamp(float(timestamp)).strftime('%Y%m%d_%H%M%S')

################# ZEEK ###################
def zeek_pcap(pcap_path, thread_name="[ZEEK.thread]"):
  '''
  This function is to use zeek to analyze the pcap files with zeek (before deletion)
  @param pcap_path string - the path to the pcap file
  @param overwrite str - 'del' or timestamp to be used if overwriting prev data is not desired 
  '''
  log("-------------", highlight='blue', thread_name=thread_name)
  log("     ZEEK    ", highlight='blue', attr="bold", thread_name=thread_name)
  log("=============", highlight='blue', thread_name=thread_name)
  zeek_dir=f"{OUTPUT_DIR}/{PCAP_NAME}.zeek/"
  if not os.path.isdir(zeek_dir):
    os.makedirs(zeek_dir)
  log(f"Create Zeek output dir: {zeek_dir}", thread_name=thread_name)
  
  zeek_cmd=f"/opt/zeek/bin/zeek -C -r {pcap_path} Log::default_logdir={zeek_dir}"
  log(f"Running Zeek on {pcap_path}...results will be in {zeek_dir}", thread_name=thread_name)
  os.system(zeek_cmd)
#############################################

################# TSHARK ###################
def tshark_pcap(pcap_path, level=TSHARK_EXTRACTIONS.PACKET_LEVEL, thread_name="[TSHARK.thread #1]"):
  '''
  This function runs tshark on the pcap file
  Output path will be the same as pcap_file with a .csv suffix
  @param pcap_path string - the path to the pcap file
  @param overwrite str - 'del' or timestamp to be used if overwriting prev data is not desired 
  '''
  log("---------------------------------------", highlight='blue', thread_name=thread_name)
  log(f"   TSHARK -> {level.name}", highlight='blue', attr="bold", thread_name=thread_name)
  log("=======================================", highlight='blue', thread_name=thread_name)
  csv_filename=f"{OUTPUT_DIR}/{PCAP_NAME}"
  #main tshark command
  tshark_main_cmd=f"tshark -r {pcap_path} "
  if (SSLKEYLOGFILE is not None):
    tshark_main_cmd=f"{tshark_cmd} -o tls.keylog_file:{SSLKEYLOGFILE}"

  #### PACKET LEVEL EXTRACTION
  # this is the prettifier for the tshark session output used if TSHARK_EXTRACTIONS != PACKET_LEVEL
  awk_filter_flow_l3=' \'{print $1";"$3";"$4";"$5";"$6";"$7";"$8";"$9";"$10";"$11";"$12";"$13";"$14}\'' 
  awk_filter_flow_l4=' \'{split($1,a,":"); split($3,b,":"); print a[1]";"a[2]";"b[1]";"b[2]";"$4";"$5";"$6";"$7";"$8";"$9";"$10";"$11";"$12";"$13";"$14}\'' 
  awk_filter_endpoint=' \'{print $1";"$2";"$3";"$4";"$5";"$6";"$7}\''
  if(level == TSHARK_EXTRACTIONS.PACKET_LEVEL):
    tshark_cmd=f"{tshark_main_cmd} -T fields {TSHARK_FIELDS} -E header=y -E separator=',' -E quote=d -E occurrence=f > {csv_filename}.PACKET_LEVEL.csv"
  elif(level == TSHARK_EXTRACTIONS.FLOW_LEVEL_L3):
    create_header=f"echo 'src_ip;dst_ip;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration' > {csv_filename}.FLOW_LEVEL_L3.csv"
    tshark_cmd=f'{create_header}; {tshark_main_cmd} -q -z conv,ip |grep -v ==|grep -v IPv4|grep -v Filter|grep -v "|" |awk {awk_filter_flow_l3} >> {csv_filename}.FLOW_LEVEL_L3.csv' 
  elif(level == TSHARK_EXTRACTIONS.FLOW_LEVEL_L4_TCP):
    create_header=f"echo 'src_ip;sport;dst_ip;dport;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration' > {csv_filename}.FLOW_LEVEL_L4_TCP.csv"    
    tshark_cmd=f'{create_header}; {tshark_main_cmd} -q -z conv,tcp |grep -v ==|grep -v TCP | grep -v Filter|grep -v "|" |awk {awk_filter_flow_l4} >> {csv_filename}.FLOW_LEVEL_L4_TCP.csv' 
  elif(level == TSHARK_EXTRACTIONS.FLOW_LEVEL_L4_UDP):
    create_header=f"echo 'src_ip;sport;dst_ip;dport;recv_pkts;recv_bytes;recv_kMG;sent_pkts;sent_bytes;sent_kMG;total_pkts;total_bytes;total_kMG;rel_start_time;duration' > {csv_filename}.FLOW_LEVEL_L4_UDP.csv"    
    tshark_cmd=f'{create_header}; {tshark_main_cmd} -q -z conv,udp |grep -v ==|grep -v UDP | grep -v Filter|grep -v "|" |awk {awk_filter_flow_l4} >> {csv_filename}.FLOW_LEVEL_L4_UDP.csv' 
  elif(level == TSHARK_EXTRACTIONS.EXTRACT_ENDPOINTS):
    create_header=f"echo 'ip;all_pkts;all_bytes;sent_pkts;sent_bytes;recv_pkts;recv_bytes' > {csv_filename}.EXTRACT_ENDPOINTS.csv"
    tshark_cmd=f'{create_header}; {tshark_main_cmd} -q -z endpoints,ipv4 |grep -v ==|grep -v IPv4|grep -v Filter|grep -v "|" |awk {awk_filter_endpoint} >> {csv_filename}.EXTRACT_ENDPOINTS.csv'
  log(f"running tshark: {tshark_cmd}", thread_name=thread_name)         
  os.system(tshark_cmd)
############################################

def format_time(seconds):
    # Calculate hours, minutes, and seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    # Format the time string
    if hours > 0:
      # Return in HH:MM:SS format
      return f"{hours:02}:{minutes:02}:{secs:02}"
    elif minutes > 0:
      # Return in MM:SS format
      return f"{minutes:02}:{secs:02}"
    else:
      # Return in SS format
      return f"{secs:02} seconds"


#############
### MAIN ####
#############

ZEEK = False
TSHARK = False
if METHOD == "both":
  ZEEK = True
  TSHARK = True
elif METHOD == "zeek":
  ZEEK = True
  TSHARK = False
elif METHOD == "tshark":
  ZEEK = False
  TSHARK = True
else:
  log(f"Uknown method {METHOD} defined...Nothing to do...exiting")
  sys.exit(1)

#create a thread for zeek
#run zeek on the PCAP

zeek_thread = multiprocessing.Process(target=zeek_pcap, args=(PCAP,))
zeek_thread_start = time.time()
zeek_thread.start()

#run tshark on the pcap
# PACKET LEVEL EXTRACTION THREAD
tshark_packet_level_thread = multiprocessing.Process(target=tshark_pcap, 
                                                      args=(PCAP,
                                                            TSHARK_EXTRACTIONS.PACKET_LEVEL,
                                                            "[TSHARK.thread PKTS]"))
tshark_packet_level_thread_start = time.time()
tshark_packet_level_thread.start()


 # FLOW LEVEL EXTRACTION THREAD on LAYER-3
tshark_flow_l3_thread = multiprocessing.Process(target=tshark_pcap, 
                                                args=(PCAP,
                                                      TSHARK_EXTRACTIONS.FLOW_LEVEL_L3,
                                                      "[TSHARK.thread L3]"))
tshark_flow_l3_thread_start = time.time()
tshark_flow_l3_thread.start()

# FLOW LEVEL EXTRACTION THREAD on LAYER-4 TCP
tshark_flow_l4_tcp_thread = multiprocessing.Process(target=tshark_pcap, 
                                                    args=(PCAP,
                                                          TSHARK_EXTRACTIONS.FLOW_LEVEL_L4_TCP,
                                                          "[TSHARK.thread TCP]"))
tshark_flow_l4_tcp_thread_start = time.time()
tshark_flow_l4_tcp_thread.start()

# FLOW LEVEL EXTRACTION THREAD on LAYER-4 UDP
tshark_flow_l4_udp_thread = multiprocessing.Process(target=tshark_pcap, 
                                                    args=(PCAP,
                                                          TSHARK_EXTRACTIONS.FLOW_LEVEL_L4_UDP,
                                                          "[TSHARK.thread UDP]"))
tshark_flow_l4_udp_thread_start = time.time()
tshark_flow_l4_udp_thread.start()

# run the last TSHARK extraction as part of the main thread
tshark_endpoint_start = time.time()
tshark_pcap(PCAP, TSHARK_EXTRACTIONS.EXTRACT_ENDPOINTS, "[MAIN.thread]")
tshark_endpoint_stop = time.time()
# terminating threads
log(f"Waiting for the threads to finish...")

zeek_thread.join()
zeek_thread_stop = time.time()

tshark_packet_level_thread.join()
tshark_packet_level_thread_stop = time.time()

tshark_flow_l3_thread.join()
tshark_flow_l3_thread_stop = time.time()

tshark_flow_l4_tcp_thread.join()
tshark_flow_l4_tcp_thread_stop = time.time()

tshark_flow_l4_udp_thread.join()
tshark_flow_l4_udp_thread_stop = time.time()

log(f"Feature extraction is ready, your CSV files are in {OUTPUT_DIR}")
log(f"Time stats:")
log(f"Zeek: {zeek_thread_stop - zeek_thread_start} seconds")
log(f"Tshark (PACKET_LEVEL): {format_time(tshark_packet_level_thread_stop - tshark_packet_level_thread_start)}")
log(f"Tshark (FLOW_LEVEL_L3): {format_time(tshark_flow_l3_thread_stop - tshark_flow_l3_thread_start)}")
log(f"Tshark (FLOW_LEVEL_L4_UDP): {format_time(tshark_flow_l4_udp_thread_stop - tshark_flow_l4_udp_thread_start)}")
log(f"Tshark (FLOW_LEVEL_L4_UDP): {format_time(tshark_flow_l4_tcp_thread_stop - tshark_flow_l4_tcp_thread_start)}")
log(f"Tshark (ENDPOINTS): {format_time(tshark_endpoint_stop - tshark_endpoint_start)}")