# Suricata Setup for packetEye Live NIDS

## Install Suricata

Suricata is installed outside Python. On Linux:

```bash
sudo apt install suricata
suricata -V
```

On Windows, use WSL2 or a Linux VM for production live capture.

## Enable EVE flow logging

Edit `/etc/suricata/suricata.yaml` (or use `deploy/suricata/suricata.yaml` as reference):

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - flow
        - alert
```

Ensure `HOME_NET` matches your lab network:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
```

## Run Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

Point packetEye at the EVE file:

```
SURICATA_EVE_PATH=/var/log/suricata/eve.json
```

## Required EVE flow fields

packetEye maps these Suricata flow event fields:

| EVE field | Usage |
|-----------|-------|
| `src_ip`, `dest_ip` | Flow endpoints |
| `src_port`, `dest_port` | Ports |
| `proto` | Protocol encoding |
| `flow.start`, `flow.end` | Duration |
| `flow.bytes_toserver`, `flow.bytes_toclient` | Byte counts |
| `flow.pkts_toserver`, `flow.pkts_toclient` | Packet counts |

Flow events must have `"event_type": "flow"`.

## Test with sample EVE

```powershell
python -m pytest tests/test_suricata_mapper.py -v
```
