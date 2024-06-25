"""
Backup Elastisearch objects through the api

usage:
  ElasticBackup.py --config=<filename>
"""
import json
import requests
import os, sys
import configparser
from docopt import docopt
import hashlib


def GetElasticAPI (config, url_api ):
  if config['verbose']:
    print ("API request for : %s" % url_api)

  headers = {'Content-Type': 'application/json',}
  if config['tls']:
    method = 'https://'
  else:
    method = 'http://'
  if config['auth']:
    authentication = config['username'] + ":" + config['password'] + '@'
  else:
    authentication = ''
 
  url = method + authentication + config['server'] + ":" + config['port'] + '/' + url_api
  try:
    if config['tls']:
      r = requests.get (url, headers=headers, verify=config['cert'] )
    else:
      r = requests.get (url, headers=headers ) 
    message = json.loads(r.text)
    if r.status_code == 403: # unauthorized
      print (r.text)
      return {}
    elif r.status_code != 200:
      raise
    return message
  except:
    print ("Failed to get elasticsaerch api : %s" % url_api)      
    print (r.status_code)
    print (r.text)
    return ""


def GetElasticAPI_cat (config, url_api ):
  if config['verbose']:
    print ("API request for : %s" % url_api)

  headers = {'Content-Type': 'text/plain',}
  if config['tls']:
    method = 'https://'
  else:
    method = 'http://'
  if config['auth']:
    authentication = config['username'] + ":" + config['password'] + '@'
  else:
    authentication = ''
 
  url = method + authentication + config['server'] + ":" + config['port'] + '/' + url_api
  try:
    if config['tls']:
      r = requests.get (url, headers=headers, verify=config['cert'] )
    else:
      r = requests.get (url, headers=headers ) 
    message = r.text
    if r.status_code != 200:
      raise
    return message
  except:
    print ("Failed to get elasticsaerch api : %s" % url_api)      
    print (r.status_code)
    print (r.text)
    return ""

def CalcChecksum(filename):
  if os.path.isfile(filename):
    try:
      BLOCKSIZE = 65536
      hasher = hashlib.sha1()
      with open(filename, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
          hasher.update(buf)
          buf = afile.read(BLOCKSIZE)
        file_sha1 = hasher.hexdigest()
        filesize = os.path.getsize(filename)

        return file_sha1, filesize
    except:
      print ("Failed to calculate sha1 or filesize")
      sys.exit(1)
  else:
    filesize = 0
    file_sha1 = ''
    return file_sha1, filesize

def WriteFileJSON(config, FileName, message):
  FilePath = config['backup_folder'] +'/' + FileName
  file_sha1, filesize = CalcChecksum(FilePath)
  messageSHA = hashlib.sha1(json.dumps(message).encode()).hexdigest()

  if file_sha1 != messageSHA : #only write file if contents are different 
    if config['verbose']:
      print ("Writing file %s" % FileName)
    with open(FilePath, 'w') as outfile:
      #json.dump(message, outfile)
      json.dump(message, outfile, sort_keys=True, indent=4)

def WriteFileTXT(config, FileName, message):
  FilePath = config['backup_folder'] +'/' + FileName
  file_sha1, filesize = CalcChecksum(FilePath)
  messageSHA = hashlib.sha1(message.encode()).hexdigest()

  if file_sha1 != messageSHA :  
    if config['verbose']:
      print ("Writing file %s" % FileName)
    outfile = open(FilePath, 'w')
    outfile.write(message)

def APIGet (config, endpoint):
  #one file with all contents
  response = GetElasticAPI (config, endpoint['endpoint'] )
  WriteFileJSON(config, endpoint['FileName'], response )

  #multiple if statements to split output into multiple files
  # example : for create one file per index templates

  if 'split_by_keys' in endpoint.keys():
    #print (endpoint)
    if endpoint['split_by_keys']:
      for item in response.keys():
        FileName = endpoint['FileName'].replace('.json','') + '-' + item + '.json'
        WriteFileJSON(config, FileName, response[item])
      
  if 'split_by_keys_name' in endpoint.keys():
    if endpoint['split_by_keys_name']:
      for item in response.keys():
        for item_name in response[item]:
          if 'name' in item_name.keys():
            FileName = endpoint['FileName'].replace('.json','') + '-' + item_name['name'] + '.json'
            WriteFileJSON(config, FileName, item_name)

  #looks for json with ['hits']['hits'][] and then value of '_id' is appended to the filename
  elif 'split_by_hits_hits' in endpoint.keys():
    if endpoint['split_by_hits_hits']:
      if 'hits' in response.keys():
        if 'hits' in response['hits'].keys():
          for item in response['hits']['hits']:
            if '_id' in item.keys():
              FileName = endpoint['FileName'].replace('.json','') + '-' + item[endpoint['split_key_id']] + '.json'
              WriteFileJSON(config, FileName, item)

  elif 'split_by_name_keys' in endpoint.keys():
    if endpoint['split_by_name_keys']:
      if endpoint['split_key'] in response.keys():
        for item in response[endpoint['split_key']].keys():
          FileName = endpoint['FileName'].replace('.json','') + '-' + item + '.json'
          WriteFileJSON(config, FileName, response[endpoint['split_key']][item])

  elif 'split_by_name_list' in endpoint.keys():
    if endpoint['split_by_name_list']:
      if endpoint['split_key'] in response.keys():
        for item in response[endpoint['split_key']]:
          if endpoint['split_key_id'] in item.keys():
            FileName = endpoint['FileName'].replace('.json','') + '-' + item[endpoint['split_key_id']] + '.json'
            WriteFileJSON(config, FileName, item)

def APIGetCAT (config, endpoint):
  response = GetElasticAPI_cat (config, endpoint['endpoint'] )
  WriteFileTXT(config, endpoint['FileName'], response)

def LoadConfig(ConfigFile):
  try:
    if os.path.isfile(ConfigFile):
      config = configparser.ConfigParser()
      config.read(ConfigFile)
      if 'ElasticBackup' in config._sections:
        config_dict = {s:dict(config.items(s)) for s in config.sections()}
        RequiredConfig = ['server', 'port', 'backup_folder', 'tls', 'auth', 'cert']
        for item in RequiredConfig:
          if item not in config_dict['ElasticBackup']:
            print ("Unable to verify configuration file")
            print ("Missing %s from configuration file" % item)
            sys.exit()

        #convert text to bool
        if config_dict['ElasticBackup']['cert'] == 'False':
          config_dict['ElasticBackup']['cert']  = False
        elif config_dict['ElasticBackup']['cert'] == 'True':
          config_dict['ElasticBackup']['cert']  = True

        #set (defaults) for optional config
        if 'verbose' in config_dict['ElasticBackup'].keys():
          if config_dict['ElasticBackup']['verbose'] == 'False':
            config_dict['ElasticBackup']['verbose']  = False
          elif config_dict['ElasticBackup']['verbose'] == 'True':
            config_dict['ElasticBackup']['verbose']  = True
          else:
            config_dict['ElasticBackup']['verbose'] = False

        return config_dict['ElasticBackup']
    sys.exit()
  except:
    sys.exit()


def main():
 
  API_Endpoints_config = [ 
     { "enabled" : True, "endpoint" : "_alias", "FileName" : "alias.json", 'priv_index': ['view_index_metadata','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_component_template/*", "FileName" : "component_template.json", 'split_by_keys_name': True, 'priv_cluster': ['manage_index_templates','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_data_stream", "FileName" : "data_stream.json", 'split_by_keys_name': True, 'priv_index': ['view_index_metadata','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_enrich/policy", "FileName" : "enrich_policy.json", 'priv_cluster': ['monitor_enrich','manage_enrich','manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_index_template", "FileName" : "index_template.json", 'split_by_keys_name': True, 'priv_cluster': ['manage_index_templates','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_ilm/policy", "FileName" : "ilm_policy.json", 'split_by_keys': True, 'priv_cluster': ['read_ilm','manage_ilm','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_inference/_all", "FileName" : "inference_all.json", 'priv_cluster': ['manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_ingest/pipeline", "FileName" : "ingest_pipeline.json", 'split_by_keys': True, 'priv_cluster': ['read_pipeline','manage_ingest_pipelines','manage_pipeline','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_logstash/pipeline", "FileName" : "logstash_pipeline.json", 'priv_cluster': ['manage_logstash_pipelines','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_ml/anomaly_detectors", "FileName" : "ml_anomaly_detectors.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_ml/calendars/_all", "FileName" : "ml_calendars_all.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_ml/calendars/_all/events", "FileName" : "ml_calendars_all_events.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_ml/data_frame/analytics", "FileName" : "ml_data_frameanalytics.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_ml/filters/", "FileName" : "ml_filters.json", 'priv_cluster': ['manage_ml','manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_ml/datafeeds/", "FileName" : "ml_datafeeds.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_snapshot", "FileName" : "snapshot.json", 'priv_cluster': ['monitor_snapshot','create_snapshot','manage','all'] },
     { "enabled" : True, "endpoint" : "_transform", "FileName" : "transform.json", 'split_by_name_list' : True, 'split_key': 'transforms', 'split_key_id' : 'id', 'priv_cluster': ['monitor_data_frame_transforms','monitor_transform','manage_data_frame_transforms','manage_transform','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_watcher/_query/watches", "FileName" : "watcher_query_watches.json", 'split_by_name_list' : True, 'split_key': 'watches', 'split_key_id' : '_id', 'priv_cluster': ['monitor_watcher','manage_watcher','monitor','manage','all'] },
     # remove key 'priv_index_name' if this api call has issues
     { "enabled" : True, "endpoint" : ".watches/_search", "FileName" : "watches_search.json", 'split_by_hits_hits': True, 'split_key_id' : '_id', 'priv_index_name': '.watches', 'priv_index': ['read','all'] }, 
      ]

  API_Endpoints_information = [ 
     { "enabled" : True, "endpoint" : "_application/analytics", "FileName" : "application_analytics.json", 'priv_cluster': ['manage_behavioral_analytics','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_application/search_application/", "FileName" : "application_search_application.json", 'priv_cluster': ['manage_search_application','manage','all']}, 
     { "enabled" : True, "endpoint" : "_ccr/auto_follow", "FileName" : "ccr_auto_follow.json", 'priv_cluster': ['manage_ccr','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_data_stream/*/_lifecycle", "FileName" : "data_stream_lifecycle.json", 'priv_index': ['manage_data_stream_lifecycle','view_index_metadata','manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_features", "FileName" : "features.json", 'priv_cluster': ['manage','all']},
     { "enabled" : True, "endpoint" : "_license", "FileName" : "license.json", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_license/basic_status", "FileName" : "license_basic_status.json", 'priv_cluster': ['manage','all'] },
     { "enabled" : True, "endpoint" : "_license/trial_status", "FileName" : "license_trial_status.json", 'priv_cluster': ['manage','all'] },
     { "enabled" : True, "endpoint" : "_migration/deprecations", "FileName" : "migration_deprecations.json", 'priv_cluster': ['manage','all'] }, 
     { "enabled" : True, "endpoint" : "_migration/system_features", "FileName" : "migration_system_features.json", 'priv_cluster': ['manage','all'] }, 
     { "enabled" : True, "endpoint" : "_ml/info", "FileName" : "ml_info.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_nodes", "FileName" : "nodes.json", 'split_by_name_keys' : True, 'split_key': 'nodes', 'priv_cluster': ['monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_query_rules", "FileName" : "query_rules.json", 'priv_cluster': ['manage_search_query_rules','manage','all']  },
     { "enabled" : True, "endpoint" : "_script_context", "FileName" : "script_context.json", 'priv_cluster': ['manage','all'] },
     { "enabled" : True, "endpoint" : "_script_language", "FileName" : "script_language.json", 'priv_cluster': ['manage','all'] },
     { "enabled" : True, "endpoint" : "_security/api_key", "FileName" : "security_apikey.json", 'priv_cluster': ['read_security','manage_api_key','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/privilege/_builtin", "FileName" : "security_privilege_builtin.json", 'priv_cluster': ['read_security','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/privilege", "FileName" : "security_privilege.json", 'split_by_keys': True, 'priv_cluster': ['read_security','manage_security','all'] },  #verify on different cluster 
     { "enabled" : True, "endpoint" : "_security/_query/api_key", "FileName" : "security_query_api_key.json", 'priv_cluster': ['manage_own_api_key','read_security','manage_api_key','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/role_mapping", "FileName" : "security_role_mapping.json", 'priv_cluster': ['read_security','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/role", "FileName" : "security_role.json", 'split_by_keys': True, 'priv_cluster': ['read_security','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/service", "FileName" : "security_service.json", 'priv_cluster': ['manage_service_account','read_security','manage_security','all']  }, 
     { "enabled" : True, "endpoint" : "_security/settings", "FileName" : "security_settings.json", 'priv_cluster': ['read_security','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/user", "FileName" : "security_user.json", 'split_by_keys': True, 'priv_cluster': ['read_security','manage_security','all'] },
     { "enabled" : True, "endpoint" : "_security/user/_privileges", "FileName" : "security_user_privileges.json" },
     { "enabled" : True, "endpoint" : "_slm/policy", "FileName" : "slm_policy.json", 'split_by_keys': True, 'priv_cluster': ['read_slm','manage_slm','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_synonyms", "FileName" : "synonyms.json", 'priv_cluster': ['manage_search_synonyms','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_ssl/certificates", "FileName" : "ssl_certificates.json", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_watcher/settings", "FileName" : "watcher_settings.json", 'priv_cluster': ['manage_watcher','manage','all'] },
     { "enabled" : True, "endpoint" : "_watcher/stats", "FileName" : "watcher_stats.json", 'priv_cluster': ['monitor_watcher','manage_watcher','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_xpack", "FileName" : "xpack.json", 'priv_cluster': ['cross_cluster_search','cross_cluster_replication','monitor','manage','all'] },
      ]

  API_Endpoints_cloud = [
     { "enabled" : True, "endpoint" : "_autoscaling/capacity", "FileName" : "autoscaling_capacity.json", 'priv_cluster': ['manage_autoscaling','manage','all'] },  #returns 403 error if license not valid
     { "enabled" : True, "endpoint" : "_autoscaling/policy/*", "FileName" : "autoscaling_policy.json", 'priv_cluster': ['manage_autoscaling','manage','all'] }, #returns 403 error if license not valid
      ] 
     
  API_Endpoints_monitoring = [
     { "enabled" : True, "endpoint" : "_ccr/stats", "FileName" : "ccr_stats.json", 'priv_cluster': ['monitor','manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_connector", "FileName" : "connector.json", 'priv_cluster': ['manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_connector/_sync_job", "FileName" : "connector_sync_job.json", 'priv_cluster': ['manage','all'] }, #test on different cluster
     { "enabled" : True, "endpoint" : "_data_stream/*/_stats", "FileName" : "data_stream_stats.json" }, #needs monitor, manage or all permisions on relevant data_streams
     { "enabled" : True, "endpoint" : "_enrich/_stats", "FileName" : "enrich_stats.json", 'priv_cluster': ['monitor_enrich','manage_enrich','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_ilm/status", "FileName" : "ilm_status.json", 'priv_cluster': ['read_ilm','read_slm','manage_ilm','manage_slm','manage','all'] },
     { "enabled" : True, "endpoint" : "_ingest/geoip/stats", "FileName" : "ingest_geoip_stats.json", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_ml/anomaly_detectors/_all/model_snapshots/_all/_upgrade/_stats", "FileName" : "ml_anomaly_detectors_all_model_snapshots_all_upgrade_stats.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, #test on different cluster 
     { "enabled" : True, "endpoint" : "_ml/anomaly_detectors/_all/results/overall_buckets", "FileName" : "ml_anomaly_detectors_all_results_overall_buckets.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_ml/anomaly_detectors/_stats", "FileName" : "ml_anomaly_detectors_stats.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_ml/datafeeds/_stats", "FileName" : "ml_datafeeds_stats.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_ml/data_frame/analytics/_stats", "FileName" : "ml_data_frame_analytics_stats.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_ml/memory/_stats", "FileName" : "ml_memory_stats.json", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_nodes/shutdown", "FileName" : "nodes_shutdown.json", 'priv_cluster': ['manage','all'] }, 
     { "enabled" : True, "endpoint" : "_recovery", "FileName" : "recovery.json" },
     { "enabled" : True, "endpoint" : "_segments", "FileName" : "segments.json" },
     { "enabled" : True, "endpoint" : "_shard_stores", "FileName" : "shard_stores.json" }, 
     { "enabled" : True, "endpoint" : "_slm/stats", "FileName" : "slm_stats.json", 'priv_cluster': ['manage_slm','manage','all'] },  
     { "enabled" : True, "endpoint" : "_slm/status", "FileName" : "slm_status.json", 'priv_cluster': ['manage_slm','manage','all'] },
     { "enabled" : True, "endpoint" : "_searchable_snapshots/stats", "FileName" : "searchable_snapshots_stats.json", 'priv_cluster': ['manage','all'] }, #returns 404 if no searchable snapshot
     { "enabled" : True, "endpoint" : "/_searchable_snapshots/cache/stats", "FileName" : "searchable_snapshots_cache_stats.json", 'priv_cluster': ['manage','all'] },
     { "enabled" : True, "endpoint" : "_snapshot/_status", "FileName" : "snapshot_status.json", 'priv_cluster': ['monitor_snapshot','create_snapshot','manage','all'] }, 
     { "endpoint" : "_stats", "FileName" : "stats.json", "enabled" : True },
     { "enabled" : True, "endpoint" : "_transform/_stats", "FileName" : "transform_stats.json", 'split_by_name_list' : True, 'split_key': 'transforms', 'split_key_id' : 'id', 'priv_cluster': ['monitor_data_frame_transforms','monitor_transform','manage_data_frame_transforms','manage_transform,monitor,manage','all']}, 
     { "enabled" : True, "endpoint" : "_watcher/stats", "FileName" : "watcher_stats.json", 'priv_cluster': ['monitor_watcher','manage_watcher','monitor','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_xpack/usage", "FileName" : "xpack_usage.json", 'priv_cluster': ['monitor','manage','all'] }
      ] 

  API_Endpoints_cat = [
     { "enabled" : True, "endpoint" : "_cat/aliases", "FileName" : "cat_aliases.txt", 'priv_index': ['view_index_metadata','manage','all'] }, 
     { "enabled" : True, "endpoint" : "_cat/allocation", "FileName" : "cat_allocation.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/component_templates", "FileName" : "cat_component_templates.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/count", "FileName" : "cat_count.txt" },
     { "enabled" : True, "endpoint" : "_cat/fielddata", "FileName" : "cat_fielddata.txt", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/health", "FileName" : "cat_health.txt", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/indices", "FileName" : "cat_indices.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/master", "FileName" : "cat_master.txt", 'priv_cluster':  ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/nodeattrs", "FileName" : "cat_nodeattrs.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/nodes", "FileName" : "cat_nodes.txt" , 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/pending_tasks", "FileName" : "cat_pending_tasks.txt", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/plugins", "FileName" : "cat_plugins.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/recovery", "FileName" : "cat_recovery.txt" },
     { "enabled" : True, "endpoint" : "_cat/repositories", "FileName" : "cat_repositories.txt", 'priv_cluster': ['monitor_snapshot','create_snapshot','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/segments", "FileName" : "cat_segments.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/shards", "FileName" : "cat_shards.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/snapshots", "FileName" : "cat_snaphots.txt", 'priv_cluster': ['monitor_snapshot','create_snapshot','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/tasks", "FileName" : "cat_tasks.txt", 'priv_cluster': ['monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/templates", "FileName" : "cat_templates.txt", 'priv_cluster': ['manage_index_templates','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/thread_pool", "FileName" : "cat_thread_pool.txt", 'priv_cluster': ['read_ccr','transport_client','cross_cluster_replication','manage_ccr','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/transforms/_all", "FileName" : "cat_transforms.txt", 'priv_cluster': ['monitor_data_frame_transforms','monitor_transform','manage_data_frame_transforms','manage_transform','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/ml/anomaly_detectors", "FileName" : "cat_ml_anomaly_detectors.txt", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/ml/data_frame/analytics", "FileName" : "cat_ml_data_frame_analytics.txt", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/ml/datafeeds", "FileName" : "cat_ml_datafeeds.txt", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] },
     { "enabled" : True, "endpoint" : "_cat/ml/trained_models", "FileName" : "cat_ml_trained_models.txt", 'priv_cluster': ['monitor_ml','manage_ml','monitor','manage','all'] }
     ]

  Endpoint_category = [ { "endpointList" : API_Endpoints_config, "enabled" : True },
                        { "endpointList" : API_Endpoints_information, "enabled" : True },
                        { "endpointList" : API_Endpoints_cloud, "enabled" : False },
                        { "endpointList" : API_Endpoints_monitoring, "enabled" : True },
                        { "endpointList" : API_Endpoints_cat, "enabled" : True }
                      ]


  options = docopt(__doc__)
  if options['--config']:
    ConfigFile=options['--config']
    config = LoadConfig(ConfigFile)

    if not os.path.exists(config['backup_folder']):
      os.mkdir(config['backup_folder'])

    #get security privilege of current user - skips api calls that will fail
    privileges = GetElasticAPI (config, '_security/user/_privileges' )

    #loop through enabled API calls and create backups 
    if os.path.exists(config['backup_folder']):
      for endPointsList in Endpoint_category:
        if endPointsList['enabled']: 
          for i in endPointsList['endpointList']:
            if i['enabled']:
               if 'priv_index' in i.keys():
                 if 'priv_index_name' in i.keys():
                   privileges_fail = True
                   for privileges_indices in privileges['indices']:
                     for j in privileges_indices['names']:
                       if i['priv_index_name'] in j: 
                         if (set(i['priv_index']) & set(privileges_indices['privileges'])):
                           privileges_fail = False
                   if privileges_fail:
                     if config['verbose']:
                       print ("Account does not have required index privilege for API call (%s), Requires index privilege (%s) for indices : %s " % (i['endpoint'], i['priv_index'], i['priv_index_name']))
                     continue

                 else:
                   privileges_fail = True
                   for privileges_indices in privileges['indices']:
                     if (set(i['priv_index']) & set(privileges_indices['privileges'])):
                       privileges_fail = False
                   if privileges_fail:
                     if config['verbose']:
                       print ("Account does not have required index privilege for API call (%s), Requires index privilege : %s " % (i['endpoint'], i['priv_index']))
                     continue

               if 'priv_cluster' in i.keys():
                 if not (set(i['priv_cluster']) & set(privileges['cluster'])):
                   if config['verbose']:
                     print ("Account does not have required cluster privilege for API call (%s), Requires cluster privilege : %s " % (i['endpoint'], i['priv_cluster']))  
                   continue

               # if no privilege issues found, make api call 
               if i['endpoint'].startswith('_cat'):
                 APIGetCAT (config, i)
               else:
                 APIGet (config, i)

  
if __name__ == "__main__":
  main()

