# KibanaBackup

Backup Kibana spaces and objects using the Kibana api

usage:
```
  python3 KibanaBackup.py --config=KibanaBackup.conf
```

This program creates ndjson files that are the compatible with the "Stack Management" -> "Saved Objects" feature in Kibana. They can be imported back into Kibana by using the "Import" in Kibana

# Installation

Please update the KibanaBackup.conf to match your environment.
