# pcap_tool

Use to extract potential RTP streams from a pcap into a dedicated file.

pcap_tool uses `libpcap` (https://www.tcpdump.org/)

# Build

```
gcc pcap_tool.c -o pcap_tool -lpcap
```

## Usage

```./pcap_tool INPUT_FILE```

e.g.:

```./pcap_tool capture.pcap```

`pcap_tool` will dump the potential RTP streams into separate files with format `stream-0x<SSRC>.pcap`.

