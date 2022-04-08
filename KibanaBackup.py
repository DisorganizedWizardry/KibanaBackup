"""
Backup Kibana spaces and objects using the Kibana api

usage:
  KibanaBackup.py --config=<filename>
"""
import json
import requests
import os, sys
import configparser
from docopt import docopt
import hashlib

import urllib3
urllib3.disable_warnings()

def GetKibanaAPI (config, url_api ):
  headers = {'Content-Type': 'application/json',}

  if config['tls']:
    method = 'https://'
  else:
    method = 'http://'

  if config['auth']:
    authentication = config['username'] + ":" + config['password'] + '@'
  else:
    authentication = ''
 
  try:
    url = method + authentication + config['server'] + ":" + config['port'] + '/' + url_api
    if config['tls']:
      r = requests.get (url, headers=headers, verify=False)
    else:
      r = requests.get (url, headers=headers ) 

    message = json.loads(r.text)
    if r.status_code != 200:
      raise
    return message
  except:
    print ("Failed to get kibana api")      
    print (r.text)
    return ""

def GetSpaceObject(config, space, Object, default):
  headers = {'Content-Type': 'application/json', 'kbn-xsrf': 'true' }

  if config['tls']:
    method = 'https://'
  else:
    method = 'http://'

  if config['auth']:
    authentication = config['username'] + ":" + config['password'] + '@'
  else:
    authentication = ''
  
  #There is different api call for the default space
  if default: 
    api_query = '/api/saved_objects/_export'
  else:
    api_query = '/s/' + space + '/api/saved_objects/_export'

  url = method + authentication + config['server'] + ":" + config['port'] + api_query 
  post_data = json.dumps({ 'type': Object })

  try:
    if config['tls']:
      print ("not verifying the tls cert!! - feature not available yet")
      r = requests.post (url, headers=headers, data=post_data, verify=False)
    else:
      r = requests.post (url, headers=headers, data=post_data ) 

    #need to save export.ndjson file
    if r.status_code == 200:
      if r.headers['content-disposition']:
        export = r.content
        return export
  except:
    print ("Failed to export space objects")      
    return ""

def CalcChecksumFile(filename):
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

def WriteFileJSON(config, FileName, message):
  FilePath = config['backup_folder'] +'/' + FileName
  with open(FilePath, 'w') as outfile:
    json.dump(message, outfile)

#Write ndjson file from byte array
def WriteFileObject(config, FileName, message):
  FilePath = config['backup_folder'] +'/' + FileName
  outfile = open(FilePath, 'wb')
  outfile.write(message)


def GetSpaceObjects(config, space, SeperateObjectTypes):
  #which types of saved objects are exported - check this after Kibana is upgraded
  SavedObjectTypes = ['config','url','index-pattern','query','visualization','canvas-element','canvas-workpad','graph-workspace','dashboard','map','search','tag','map','lens','infrastructure-ui-source','metrics-explorer-view','inventory-view','apm-indices']

  #Export all objects in a space
  if space == 'default': #default space has a different api url
    message = GetSpaceObject(config, space, SavedObjectTypes, True)
  else:
    message = GetSpaceObject(config, space, SavedObjectTypes, False)
  FileName = "SavedObjects_" + space + ".ndjson"
  WriteFileObject(config, FileName, message)

  #Export each object as a seperate file
  if SeperateObjectTypes:
    for Object in SavedObjectTypes:
      print ("Exporting Object : %s in space : %s" % (Object, space))
      if space == 'default': #default space has a different api url
        message = GetSpaceObject(config, space, Object, True)
      else:
        message = GetSpaceObject(config, space, Object, False)

      FileName = "SavedObjects_" + space + "_" + Object + ".ndjson"
      WriteFileObject(config, FileName, message)


def GetSpaces(config, SeperateObjectTypes):
  spaces_json = GetKibanaAPI(config, "api/spaces/space")
  FileName = 'kibana_spaces.json'
  WriteFileJSON(config, FileName, spaces_json)

  for space in spaces_json:
    print ("Export Objects for Space : %s" % space['id'])
    GetSpaceObjects(config, space['id'], SeperateObjectTypes)


def GetRoles(config):
  roles_json = GetKibanaAPI(config, "api/security/role")
  FileName = 'kibana_roles.json'
  WriteFileJSON(config, FileName, roles_json)



#load config
def LoadConfig(ConfigFile):
  try:
    if os.path.isfile(ConfigFile):
      config = configparser.ConfigParser()
      config.read(ConfigFile)
      if 'KibanaBackup' in config._sections:
        config_dict = {s:dict(config.items(s)) for s in config.sections()}
        RequiredConfig = ['server', 'port', 'backup_folder', 'tls', 'auth']
        for item in RequiredConfig:
          if item not in config_dict['KibanaBackup']:
            print ("Unable to verify configuration file")
            print ("Missing %s from configuration file" % item)
            return None
        #convert tls True/False string to bool
        if config_dict['KibanaBackup']['tls'] == 'True':
          config_dict['KibanaBackup']['tls'] = True
        else:
          config_dict['KibanaBackup']['tls'] = False

        if config_dict['KibanaBackup']['auth'] == 'True':
          config_dict['KibanaBackup']['auth'] = True
        else:
          config_dict['KibanaBackup']['auth'] = False
 
        return config_dict['KibanaBackup']
    return None
  except:
    return None


def main():
  #which types of saved objects are exported
  SavedObjectTypes = ['config','url','index-pattern','query','visualization','canvas-element','canvas-workpad','graph-workspace','dashboard','map','search','tag','map','lens','infrastructure-ui-source','metrics-explorer-view','inventory-view','apm-indices']

  options = docopt(__doc__)
  if options['--config']:
    ConfigFile=options['--config']
    config = LoadConfig(ConfigFile)
    if config is None:
      print ("Failed to load config")
      return

    if not os.path.exists(config['backup_folder']):
      os.mkdir(config['backup_folder'])

    if os.path.exists(config['backup_folder']):
      GetRoles(config)

      #set to true if you want to export a seperate file for each object type in a space
      SeperateObjectTypes = False 
      GetSpaces(config, SeperateObjectTypes)


if __name__ == "__main__":
  main()

