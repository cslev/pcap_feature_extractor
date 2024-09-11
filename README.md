# Feature Extraction from PCAP files
This tool is for extracting features from PCAP files at different granularity levels.

# Requirements
The python script uses only defauly Python packages but relies on Linux tools,
namely `zeek` and `tshark`.
Both are freely available and can be installed through your OS packet manager.
However, there is a `bootstrap.sh` script prepared in this repo that does the 
heavylifting for you. Currently Ubuntu and Debian systems are supported via the
`bootstrap.sh`.

# Usage
## Bootstrap
To bootstrap your system, i.e., to install `zeek` and `tshark` use `bootstrap.sh`.
```
This script install necessary tools for the feature extraction. 
In particular, it install Zeek and tshark with all their requirements. 
Supported OSes are Ubuntu and Debian (only)
Example: sudo ./bootstrap 
        -d <DISTRO>: enforce distro here (e.g., ubuntu,debian) (Default: read from /etc/os-release).
        -v <DISTRO_VER>: enforce distro version number (e.g., 22.04) Use in tandem with -d. (Default: read from /etc/os-release)
```
As can be seen you either rely on the details your OS provides, or if you are sure that
you are running a certain flavor of Debian or Ubuntu, but the `/etc/os-release` would return
something different (like in my case, it is `pop`), you can enforce the script to download
and (try to) install `zeek` on your system.

## Feature Extraction
To get different levels of features from your raw PCAP file, use `extract_features.py`.
```
usage: extract_features.py [-h] -i PCAP [-m METHOD] [-s SSLKEYLOGFILE] [-o OUTPUT_DIR]

Feature Extraction usage

options:
  -h, --help            show this help message and exit
  -i PCAP, --input PCAP
                        The pcap file to extract features from
  -m METHOD, --method METHOD
                        The methods to be used, possible values: 'both', 'tshark', 'zeek' (Default: both)
  -s SSLKEYLOGFILE, --sslkeylogfile SSLKEYLOGFILE
                        In case you have SSLKEYLOGFILE, tshark can decrypt payloads (Default: None
  -o OUTPUT_DIR, --outputdir OUTPUT_DIR
                        Output directory (Default: ${HOME}/git/pcap_feature_extractor/output_dir)
```

It will generate AI/ML-ready CSV files that will be saved in the `OUTPUT_DIR` using your original PCAP-file name as basename, appended with the granularity, e.g., PACKET_LEVEL.

These levels are as follows:
 - `PACKET_LEVEL` -> standard tshark output from PCAP, every row represents a single packet's metadata
 - `FLOW_LEVEL_L3` -> aggregated data on Layer-3 flow level. Packets and bytes sent and received between two different IP address
 - `FLOW_LEVEL_L4_UDP/TPC` -> aggregated data on Layer-4 flow level. Packets and bytes sent and received between two source_ip:source_port and destination_ip:destination_port. `UDP` is for UDP connections, while `TCP` is for the TCP connections.
 - `EXTRACT_ENDPOINTS` -> aggregated data per source IP: each host and its corresponding sent and received data.
 - `.zeek` -> output generated automatically via Zeek.

 The script runs each submodule as a separate thread to make processing parallel, hence fast.
 At the end, it also provides you information about how much time each thread took.

 
