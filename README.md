This program was created to backup the configuration options that are not backed up in an elasticsearch snapshot. 

The files are saved in multiple json files, which allow individual configuration items to be restored. The files are also written in a diff friendly, json format. It is possible to run this backup as a daily backup and store in a git repository.

If this script is run with an account that does not have full permissions to an elasticsearch cluster, it will still create a partial backup, backing up everything that it has access to.

# KibanaBackup

Backup Kibana spaces and objects using the Kibana api

usage:
```
  python3 KibanaBackup.py --config=KibanaBackup.conf
```

This program creates ndjson files that are the compatible with the "Stack Management" -> "Saved Objects" feature in Kibana. They can be imported back into Kibana by using the "Import" in Kibana

# ElasticBackup

Backup elasticsearch configuration via the elassticsearch REST api.

usage:
```
  python3 ElasticBackup.py --config=ElasticBackup.conf
```

Multiple ndjson files will be created for each feature of an elasticsearch cluster. They can be imported back into elasticsearch by using the Dev Tools console in Kibana

Some items that are backed up are:
* Index template and component templates
* ilm policies
* enrich policies
* logstash and ingest pipelines
* aliases
* datastreams
* transforms
* watcher
* user and role permissions
* cluster stats and monitoring data
* ... and more


# Installation

Please update the KibanaBackup.conf to match your environment.

# Changes

2025-04-01
* Added the ability to create folders for some items in ElasticBackup. For example, all index templates can now be writted into a sub folder called index_templates.
