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

def GetKibanaAPI (config, url_api, post_data ):
  if config['verbose']:
    print ("API request for : %s" % url_api)

  headers = {'Content-Type': 'application/json', 'kbn-xsrf': 'true' }

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
      r = requests.post (url, headers=headers, data=post_data, verify=config['cert'] )
    else:
      r = requests.post (url, headers=headers, data=post_data ) 
    message = r.text #kibana spaces export is ndjson 

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
      json.dump(message, outfile, indent=4)

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
  response = GetElasticAPI (config, endpoint['endpoint'] )
  WriteFileJSON(config, endpoint['FileName'], response )

  if 'export_spaces' in endpoint.keys():
    if endpoint['export_spaces']:
      for space in response:
        if config['verbose']:
          print ("Export Objects for Space : %s" % space['id'])

        #There is a different api call for the default space
        if space['id'] == 'default':
          api_query = '/api/saved_objects/_export'
        else:
          api_query = 's/' + space['id'] + '/api/saved_objects/_export'

        post_data = json.dumps({ 'type': config['SavedObjectTypes'] })

        response = GetKibanaAPI (config, api_query, post_data)
        FileName = "SavedObjects_" + space['id'] + ".json"
        WriteFileJSON(config, FileName, response )

        if 'split_space_objects' in endpoint.keys():
          if endpoint['split_space_objects']:
            for Object in config['SavedObjectTypes']:
              if config['verbose']:
                print ("Exporting Object : %s in space : %s" % (Object, space['id']))
              post_data = json.dumps({ 'type': Object })
              response = GetKibanaAPI (config, api_query, post_data = post_data)
              FileName = "SavedObjects_" + space['id'] + "_" + Object + ".json"
              WriteFileJSON(config, FileName, response )
 
  #Fleet policies
  if 'split_by_keys_items_id' in endpoint.keys():
    if endpoint['split_by_keys_items_id']:
      for item in response["items"]:
        if 'id' in item:
          FileName = endpoint['FileName'].replace('.json','') + '-' + item['id'] + '.json'
          policy = GetElasticAPI (config, endpoint['endpoint'] + '/' + item['id'] )
          WriteFileJSON(config, FileName, policy )

def LoadConfig(ConfigFile):
  try:
    if os.path.isfile(ConfigFile):
      config = configparser.ConfigParser()
      config.read(ConfigFile)
      if 'KibanaBackup' in config._sections:
        config_dict = {s:dict(config.items(s)) for s in config.sections()}
        RequiredConfig = ['server', 'port', 'backup_folder', 'tls', 'auth', 'cert']
        for item in RequiredConfig:
          if item not in config_dict['KibanaBackup']:
            print ("Unable to verify configuration file")
            print ("Missing %s from configuration file" % item)
            sys.exit()

        #convert text to bool
        if config_dict['KibanaBackup']['tls'] == 'False':
          config_dict['KibanaBackup']['tls']  = False
        elif config_dict['KibanaBackup']['tls'] == 'True':
          config_dict['KibanaBackup']['tls']  = True

        if config_dict['KibanaBackup']['cert'] == 'False':
          config_dict['KibanaBackup']['cert']  = False
        elif config_dict['KibanaBackup']['cert'] == 'True':
          config_dict['KibanaBackup']['cert']  = True

        #set (defaults) for optional config
        if 'verbose' in config_dict['KibanaBackup'].keys():
          if config_dict['KibanaBackup']['verbose'] == 'False':
            config_dict['KibanaBackup']['verbose']  = False
          elif config_dict['KibanaBackup']['verbose'] == 'True':
            config_dict['KibanaBackup']['verbose']  = True
          else:
            config_dict['KibanaBackup']['verbose'] = False

        #The Saved Object Type keeps changing with new releases
        if 'SavedObjectTypes' not in config_dict['KibanaBackup'].keys():
          #list of object from kibana 8.12.2
          config_dict['KibanaBackup']['SavedObjectTypes'] = [ "config","config-global","url","index-pattern","action","query","tag","graph-workspace","alert","search","visualization","event-annotation-group","dashboard","lens","cases","metrics-data-source","links","canvas-element","canvas-workpad","osquery-saved-query","osquery-pack","csp-rule-template","map","infrastructure-monitoring-log-view","threshold-explorer-view","uptime-dynamic-settings","synthetics-privates-locations","infrastructure-ui-source","inventory-view","metrics-explorer-view","apm-indices","apm-service-group","apm-custom-dashboards"]

        return config_dict['KibanaBackup']
    sys.exit()
  except:
    sys.exit()


def main():
 
  API_Endpoints_kibana = [
     { "enabled" : True, "endpoint" : "api/security/role", "FileName" : "kibana_roles.json" },
     #Exports Kibana Space Objects
     #splitting space object into discrete files is disabled by default
     { "enabled" : True, "endpoint" : "api/spaces/space", "FileName" : "kibana_spaces.json", "export_spaces" : True, "split_space_objects" : False },
     { "enabled" : True, "endpoint" : "api/fleet/agent_policies", "FileName" : "fleet_agent_policies.json", "split_by_keys_items_id" : True },

     ]

  Endpoint_category = [ { "endpointList" : API_Endpoints_kibana, "enabled" : True }
                      ]


  options = docopt(__doc__)
  if options['--config']:
    ConfigFile=options['--config']
    config = LoadConfig(ConfigFile)

    if not os.path.exists(config['backup_folder']):
      os.mkdir(config['backup_folder'])

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
