# pcap_tool

Use to extract potential RTP streams from a pcap into a dedicated file.

pcap_tool uses `libpcap` (https://www.tcpdump.org/)

# Build

```gcc pcap_tool.c -o pcap_tool -l pcap```

## Usage

```./pcap_tool INPUT_FILE OUTPUT_FILE```

e.g.:

```./pcap_tool capture.pcap rtp_streams.pcap```
