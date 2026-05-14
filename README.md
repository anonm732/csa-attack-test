# csa-attack-test

802.11 Channel Switch Announcement Attack Test.

## Dependency

- libpcap

```bash
sudo apt install libpcap-dev
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Usage

```
syntax : csa-attack-test <interface> <ap mac> <channel offset> [<station mac>]
sample : csa-attack-test mon0 00:11:22:33:44:55 6
         csa-attack-test mon0 00:11:22:33:44:55 6 66:77:88:99:AA:BB
```

