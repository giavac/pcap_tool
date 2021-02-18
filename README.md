# pcap_tool

Use to extract potential RTP streams from a pcap into a dedicated file.

pcap_tool uses `libpcap` (https://www.tcpdump.org/)

e.g. for debian:
```
apt install libcap-dev
```

# Build

```
gcc pcap_tool.c -o pcap_tool -lpcap
```

## Usage

```
./pcap_tool [-d] INPUT_FILE
```

e.g.:

```
./pcap_tool capture.pcap
```

`pcap_tool` will dump the potential RTP streams into separate files with format `stream-0x<SSRC>.pcap`.

Use `-d` to print debug messages (very verbose at it applies to most of the packets in the pcap), e.g.

```
./pcap_tool -d capture.pcap
```

