# Build

```shell
brew install libimobiledevice libplist
```


# Usage

```shell
# save to pcap
idevicecap -n processname -o ios.pcap

# redirect to stdout so we can use with wireshark
idevicecap -n processname | wireshark -k -i -
```