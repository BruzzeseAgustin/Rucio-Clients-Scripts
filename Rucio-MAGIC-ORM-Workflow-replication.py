#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# coding: utf-8

# In[1]:


from __future__ import absolute_import, division, print_function

import sys,os,os.path

# Set Rucio virtual environment configuration 

os.environ['RUCIO_HOME']=os.path.expanduser('~/rucio')

import io,json,linecache,logging,os,os.path,random,re,time,uuid,zipfile,string,pathlib,time,pytz,graphyte,socket,logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import numpy as np 
from urllib.parse import urlunsplit

from io import StringIO

from rucio.rse import rsemanager as rsemgr
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
import rucio.rse.rsemanager as rsemgr
from rucio.client.ruleclient import RuleClient
from rucio.client.uploadclient import UploadClient
from rucio.client.downloadclient import DownloadClient
from rucio.common.utils import (adler32, detect_client_location, 
                                execute, generate_uuid, md5, 
                                send_trace, GLOBALLY_SUPPORTED_CHECKSUMS)
from rucio.common.exception import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    AccessDenied, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)


import sys
sys.path.append("/usr/lib64/python3.6/site-packages/")
import gfal2
from gfal2 import (
    Gfal2Context,
    GError,
)


# In[2]:


# Rucio settings 

## Remember to always have an alive and valid proxy before executing the script

## account user
account='root'
auth_type='x509_proxy'

CLIENT = Client(account=account, auth_type=auth_type)
didc = DIDClient(account=account, auth_type=auth_type)
repc = ReplicaClient(account=account, auth_type=auth_type)
client = Client(account=account, auth_type=auth_type)
uploadClient = UploadClient()
downloadClient = DownloadClient()
rulesClient = RuleClient()

## user scope 
Default_Scope = 'test-root'

# Get list of all RSEs 
default_rses = list(client.list_rses())
rses_lists = []
for single_rse in default_rses :
    rses_lists.append(single_rse['rse'])

print(rses_lists)

# Gfal settings 
gfal = Gfal2Context()

print(json.dumps(client.whoami(), indent=4, sort_keys=True))
print(json.dumps(client.ping(), indent=4, sort_keys=True))

sys.path.append("/usr/lib64/python3.6/site-packages/")
import gfal2
from gfal2 import Gfal2Context, GError
gfal2.set_verbose(gfal2.verbose_level.debug)

gfal = Gfal2Context()


# In[3]:


# Specific Functions for Rucio 

## Get files from base mouting point of RSE defined on DEFAULT_PATH
def check_directory(path):

    try :
        full_path = gfal.listdir(str(path))
        is_dir_or_not = True        
    except:
        is_dir_or_not = False
        
    return(is_dir_or_not)

def scrap_through_dir(dir_path) : 

    print("*-Listin files from url : %s" % dir_path)
    all_files = []

    # Itinerate over all the entries  
    listFiles = gfal.listdir(str(dir_path))
    for file in [x for x in listFiles if x != '.' if x != '..']:
        # Create full Path 
        fullPath = os.path.join(dir_path, file)
        #print('|-- '+ fullPath)
        is_dir = check_directory(fullPath) 
        # If entry is a directory then get the list of files in
        if is_dir == True :
            print('|--- ' + fullPath + ' its a directory ')
            all_files = all_files + scrap_through_dir(fullPath)

        else :
            print('|--- '+ fullPath + ' its a file')
            all_files.append(fullPath) 
            
    return(all_files)
                                                                        
def scrap_through_files(dir_path) : 

    print("*-Listin files from url : %s" % dir_path)
    all_files = []

    # Itinerate over all the entries  
    listFiles = gfal.listdir(str(dir_path))
    for file in [x for x in listFiles if x != '.' if x != '..']:
        # Create full Path 
        fullPath = os.path.join(dir_path, file)
        #print('|-- '+ fullPath)
        is_dir = check_directory(fullPath) 
        # If entry is a directory then get the list of files in
        if is_dir == True :
            pass
        
        else :
            print('|--- '+ fullPath + ' its a file')
            all_files.append(fullPath) 
            
    return(all_files)

############################

# Check existence of file at RSE
def check_replica(myscope, lfn, dest_rse):
    """
    Check if a replica of the given file at the site already exists.
    """

    replicas = list(
        client.list_replicas([{
            'scope': myscope,
            'name': lfn
        }]))
    if replicas:
        replicas = replicas[0]
        if 'rses' in replicas:
            for rse in replicas['rses']:
                if rse == dest_rse : 
                    logger.debug("%s:%s already has a replica at %s",
                                 myscope, lfn, rse)
                    print("'|  -  -  -  - - %s:%s already has a replica at %s" %
                                     (myscope, lfn, rse))
                    return True

    return False

        
def experiment_metadata(did, key, value, myscope='test-root') :
    try :
        set_meta = didc.set_metadata(scope=myscope, name=did, key=key, value=value, recursive=False)
        return(True)
    except : 
        return(False)  


# In[ ]:



# Global variables definition : 

def get_rse_url(rse):
    """
    Return the base path of the rucio url
    """
    rse_settings = rsemgr.get_rse_info(rse)
    protocol = rse_settings['protocols'][0]

    schema = protocol['scheme']
    prefix = protocol['prefix']
    port = protocol['port']
    rucioserver = protocol['hostname']

    if schema == 'srm':
        prefix = protocol['extended_attributes'][
            'web_service_path'] + prefix
    url = schema + '://' + rucioserver
    if port != 0:
        url = url + ':' + str(port)
    rse_url = url + prefix
    return(rse_url)

# Predifine origin RSE 
DEFAULT_ORIGIN_RSE = 'ORM-NON-DET'

# Use a predefine folder to create random data 
DEFAULT_PATH = os.path.join(get_rse_url(DEFAULT_ORIGIN_RSE), 'Server-test')

print(DEFAULT_PATH)
# Predifine scope
DEFAULT_SCOPE = 'test-root'

# Destiny RSEs
rses_catch = ['PIC-DET-2'] 
# Check if our test folder still exists 
try :
    gfal.mkdir_rec(DEFAULT_PATH, 775)
except :
    PrintException()


# In[ ]:



############################

## Create Groups of DIDs

############################
def createDataset(new_dataset, myscope=Default_Scope) :         
    logger.debug("|  -  - Checking if a provided dataset exists: %s for a scope %s" % (new_dataset, myscope))
    try:
        client.add_dataset(scope=myscope, name=new_dataset)
        return(True)
    except DataIdentifierAlreadyExists:
        return(False)
    except Duplicate as error:
        return generate_http_error_flask(409, 'Duplicate', error.args[0])
    except AccountNotFound as error:
        return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
    except RucioException as error:
        exc_type, exc_obj, tb = sys.exc_info()
        logger.debug(exc_obj)

def createcontainer(name_container, myscope=Default_Scope):
    '''
    registration of the dataset into a container :
    :param name_container: the container's name
    :param info_dataset : contains, 
        the scope: The scope of the file.
        the name: The dataset name.
    '''
    logger.debug("|  -  -  - registering container %s" % name_container)

    try:
        client.add_container(scope=myscope, name=name_container)
    except DataIdentifierAlreadyExists:
        logger.debug("|  -  -  - Container %s already exists" % name_container)       
    except Duplicate as error:
        return generate_http_error_flask(409, 'Duplicate', error.args[0])
    except AccountNotFound as error:
        return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
    except RucioException as error:
        exc_type, exc_obj, tb = sys.exc_info()
        logger.debug(exc_obj)

############################

## General funciotn for registering a did into a GROUP of DID (CONTAINER/DATASET)

############################
def registerIntoGroup(n_file, new_dataset, myscope=Default_Scope):
    """
    Attaching a DID to a GROUP
    """

    print(myscope, n_file, new_dataset)
    
    try:
        client.attach_dids(scope=myscope, name=new_dataset, dids=[{'scope':myscope, 'name':n_file}])
    except RucioException:
        pass
        #logger.debug("| - - - %s already attached to %s" %(type_2['type'],type_1['type']))    

############################

## MAGIC functions 

############################
def create_groups(organization, myscope=Default_Scope) :
 
    # 2.1) Create the dataset and containers for the file
    createDataset(organization['dataset_1'].replace('%','_'))
    # 2.1.1) Attach the dataset and containers for the file
    registerIntoGroup(organization['fullname'].replace('+','_').replace('%','_'), organization['dataset_1'].replace('%','_'))

    # 2.2) Create the dataset and containers for the file
    createcontainer(organization['container_1'].replace('%','_'))
    # 2.2.1) Attach the dataset and containers for the file
    registerIntoGroup(organization['dataset_1'].replace('%','_'), organization['container_1'].replace('%','_'))

    # 2.3) Create the dataset and containers for the file
    createcontainer(organization['container_2'].replace('%','_'))
    # 2.3.1) Attach the dataset and containers for the file
    registerIntoGroup(organization['container_1'].replace('%','_'), organization['container_2'].replace('%','_'))

    # 2.4) Create the dataset and containers for the file
    createcontainer(organization['container_3'].replace('%','_'))
    # 2.4.1) Attach the dataset and containers for the file
    registerIntoGroup(organization['container_2'].replace('%','_'), organization['container_3'].replace('%','_'))

    experiment_metadata(organization['fullname'].replace('+','_'), 'run_number', str(organization['run_number'].replace('%','_')))
    experiment_metadata(organization['fullname'].replace('+','_'), 'night', str(organization['night'].replace('%','_')))
    experiment_metadata(organization['fullname'].replace('+','_'), 'datatype', str(organization['datatype'].replace('%','_')))
    experiment_metadata(organization['fullname'].replace('+','_'), 'telescope', str(organization['telescope'].replace('%','_')))

############################

## Create Rule for DIDs

############################            
def addReplicaRule(destRSE, group, myscope=Default_Scope):
    """
    Create a replication rule for one dataset at a destination RSE
    """

    type_1 = client.get_did(scope=myscope, name=group)
    logger.debug("| - - - Creating replica rule for %s %s at rse: %s" % (type_1['type'], group, destRSE))
    if destRSE:
        try:
            rule = rulesClient.add_replication_rule([{"scope":myscope,"name":group}],copies=1, rse_expression=destRSE, grouping='ALL', account=account, purge_replicas=True, asynchronous=True)
            logger.debug("| - - - - Rule succesfully replicated at %s" % destRSE)
            logger.debug("| - - - - - The %s has the following id %s" % (rule, destRSE))
            return(rule[0])
        except DuplicateRule:
            exc_type, exc_obj, tb = sys.exc_info()
            rules = list(client.list_account_rules(account=account))
            if rules : 
                for rule in rules :
                    if rule['rse_expression'] == destRSE and rule['scope'] == myscope and rule['name'] == group:
                        logger.debug('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],myscope, group, str(exc_obj)))
        except ReplicationRuleCreationTemporaryFailed:    
            exc_type, exc_obj, tb = sys.exc_info()
            rules = list(client.list_account_rules(account=account))
            if rules : 
                for rule in rules :
                    if rule['rse_expression'] == destRSE and rule['scope'] == myscope and rule['name'] == group:
                        print('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],myscope, group, str(exc_obj)))                
            
def addReplicaRule_noasync(destRSE, group, myscope=Default_Scope):
    """
    Create a replication rule for one dataset at a destination RSE
    """

    type_1 = client.get_did(scope=myscope, name=group)
    logger.debug("| - - - Creating replica rule for %s %s at rse: %s" % (type_1['type'], group, destRSE))
    if destRSE:
        try:
            rule = rulesClient.add_replication_rule([{"scope":myscope,"name":group}],copies=1, rse_expression=destRSE, grouping='ALL', account=account, purge_replicas=True)
            logger.debug("| - - - - Rule succesfully replicated at %s" % destRSE)
            logger.debug("| - - - - - The %s has the following id %s" % (rule, destRSE))
            return(rule[0])
        except DuplicateRule:
            exc_type, exc_obj, tb = sys.exc_info()
            rules = list(client.list_account_rules(account=account))
            if rules : 
                for rule in rules :
                    if rule['rse_expression'] == destRSE and rule['scope'] == myscope and rule['name'] == group:
                        logger.debug('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],myscope, group, str(exc_obj)))
        except ReplicationRuleCreationTemporaryFailed:    
            exc_type, exc_obj, tb = sys.exc_info()
            rules = list(client.list_account_rules(account=account))
            if rules : 
                for rule in rules :
                    if rule['rse_expression'] == destRSE and rule['scope'] == myscope and rule['name'] == group:
                        print('| - - - - Rule already exists %s which contains the following DID %s:%s %s' % (rule['id'],myscope, group, str(exc_obj)))    
                        
############################

## Create Rules for not registered DIDs

############################  
def outdated_register_replica(filemds, dest_RSE, org_RSE, myscope=Default_Scope):
    """
    Register file replica.
    """
    carrier_dataset = 'outdated_replication_dataset' + '-' + str(uuid.uuid4())

    creation = createDataset(carrier_dataset)

    # Make sure your dataset is ephemeral

    #client.set_metadata(scope=myscope, name=carrier_dataset, key='lifetime', value=86400) # 86400 in seconds = 1 day       

    # Create a completly new create the RULE: 
    
    for filemd in filemds :
        print(filemd, filemd['replica'][0])
        outdated = filemd['replica'][0]['name']
        print(outdated)
        registerIntoGroup(outdated, carrier_dataset)
        
    # Add dummy dataset for replicating at Destination RSE
    # Sometimes Rucio ends up with an error message like this : rucio.common.exception.RuleNotFound: No replication rule found. 
    # In order to avoid that nonsense error we do the following loop :
    for i in range(0,100):
        while True:
            try:
                # do stuff
                rule = addReplicaRule(dest_RSE, group=carrier_dataset)
                if rule != None :
                    rule_child = rule 
            except SomeSpecificException:
                continue
            break
    

    # Add dummy dataset for replicating Origin RSE
    for i in range(0,100):
        while True:
            try:
                # do stuff
                rule = addReplicaRule_noasync(org_RSE, group=carrier_dataset)
                if rule != None :
                    rule_parent = rule 
            except SomeSpecificException:
                continue
            break
    
    print(rule_child, rule_parent)
    # Create a relation rule between origin and destiny RSE, so that the source data can be deleted 
    rule = client.update_replication_rule(rule_id=rule_parent, options={'lifetime': 10, 'child_rule_id':rule_child, 'purge_replicas':True})
    logger.debug('| - - - - Creating relationship between parent %s and child %s : %s' % (rule_parent, rule_child, rule))

    # Create a relation rule between the destinity rule RSE with itself, to delete the dummy rule, whiles keeping the destiny files    
    rule = client.update_replication_rule(rule_id=rule_child, options={'lifetime': 10, 'child_rule_id':rule_child})
    logger.debug('| - - - - Creating relationship between parent %s and child %s : %s' % (rule_parent, rule_child, rule))                          
                    
############################

# First part of the script

## It creates the main rule for replication at Destinatio RSE (see rses_catch)

## Look for all files at the Origin RSE (see DEFAULT PATH)
listOfFiles = scrap_through_dir(DEFAULT_PATH)
print()


# In[ ]:




# General Functions for the script

# Import Magic naming 
from lfn2pfn_MAGIC import *

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))
    
## Get METADATA from file for RUCIO 
        
def getFileMetaData(p_file, new_scope = DEFAULT_SCOPE, origenrse=DEFAULT_ORIGIN_RSE):
    """
    Get the size and checksum for every file in the run from defined path
    """ 
    '''
    generate the registration of the file in a RSE :
    :param rse: the RSE name.
    :param scope: The scope of the file.
    :param name: The name of the file.
    :param bytes: The size in bytes.
    :param adler32: adler32 checksum.
    :param pfn: PFN of the file for non deterministic RSE  
    :param dsn: is the dataset name.
    '''
    path, name = os.path.split(p_file)
    path, folder = os.path.split(path)
    
    group = groups(p_file)
    print(group['fullname']) 
    name = name.replace('/','')
    name = name.replace('%','_') 
    
    name = name.strip('/').replace('/','')
    folder = folder.strip('/').replace('/','')

    try :
        size = gfal.stat(p_file).st_size
        checksum = gfal.checksum(p_file, 'adler32')
        
        REPLICA = [{
        'scope': new_scope,
        'name': group['fullname'].replace('+','_').replace('%','_'),
        'adler32': checksum,
        'bytes': size,
        'pfn': p_file,
        "meta": {"guid": str(generate_uuid())}
        }]
        
    except : 
        PrintException()

    Data = dict();
    Data['replica'] = REPLICA
    Data['dataset'] = folder
    Data['scope'] = new_scope

    return(Data)       


if listOfFiles :
    for destRSE in rses_catch :
        # Create an array for those files that has not been replicated 
        n_unreplicated = []
        
        # Create an array for the total dataset created 
        n_dataset = []
        n_dataset = np.array(n_dataset, dtype = np.float32)
        
        for n in range(0,len(listOfFiles)):
            name = listOfFiles[n] 
            print('|  -  ' + str(n) + ' - ' + str(len(listOfFiles)) + ' name : ' + name)
            
            # Break down the file path
            path, f_name = os.path.split(name)
            path, folder = os.path.split(path)

            # Check if file is already is registered at a particular destination RSE
            check = check_replica(myscope=DEFAULT_SCOPE, lfn=f_name, dest_rse=destRSE)
            
            # If it is registered, skip add replica 
            if check == True :
                print('|  -  - - The FILE %s already have a replica at RSE %s : %s' % (f_name, destRSE, check))
            
                                    
            # Else, if the files has no replica at destination RSE
            else : 
            
                # 2) Get the file metadata
                try :
                    metaData = getFileMetaData(name, DEFAULT_SCOPE, DEFAULT_ORIGIN_RSE)
                    print(metaData)
                    client.add_replicas(rse=DEFAULT_ORIGIN_RSE, files=metaData['replica'])
                    print('|  -  - Successfully got the information for ' + f_name)
                    # look at script lfn2pfn.py
                    group = groups(name)
                    print(group)
                    # functions : groups and create_groups
                except : 
                    PrintException()


                create_groups(group)
                
                main_rule = addReplicaRule(destRSE, group['container_3'])

                # Finally, add them to a general list 
                n_unreplicated.append(metaData)
                    
        logger.debug('Your are going to replicate %s files' % str(len(n_unreplicated)))   
        print('Your are going to replicate %s files' % str(len(n_unreplicated)))
        ## Now, create Dummy rules between the ORIGIN and DESTINATION RSEs  
        if len(n_unreplicated) > 0 :
            print('you are going to replicate: ' + str(len(n_unreplicated)))
            print(destRSE, DEFAULT_ORIGIN_RSE)
            outdated_register_replica(n_unreplicated, destRSE, DEFAULT_ORIGIN_RSE)
