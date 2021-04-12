#!/usr/bin/env python
# coding: utf-8

# In[1]:


from __future__ import absolute_import, division, print_function

__author__ = "Agustin Bruzzese"
__copyright__ = "Copyright (C) 2020 Agustin Bruzzese"

__revision__ = "$Id$"
__version__ = "0.2"

import sys
sys.path.append("/usr/lib64/python3.6/site-packages/")

import io,json,linecache,logging,os,os.path,random,re,time,uuid,zipfile,string,pathlib,time,pytz,graphyte,socket
import numpy as np 
from urllib.parse import urlunsplit
import time

from datetime import (
    datetime,
    tzinfo,
    timedelta,
    timezone,
)

from datetime import date 
from io import StringIO

# Set Rucio virtual environment configuration 
os.environ['RUCIO_HOME']=os.path.expanduser('~/rucio')
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
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime, SubscriptionDuplicate)


import gfal2
from gfal2 import (
    Gfal2Context,
    GError,
)


# In[2]:


# Rucio settings 

account='root'

didc = DIDClient(account=account)
repc = ReplicaClient(account=account)
rulesClient = RuleClient(account=account)
client = Client(account=account)
uploadClient=UploadClient()


print(json.dumps(client.whoami(), indent=4, sort_keys=True))
print(json.dumps(client.ping(), indent=4, sort_keys=True))


# In[3]:


Default_Scope = 'test-root'
today = str(time.strftime('%Y%m%d'))
dataset = today+'-metadata-' + str(uuid.uuid4())
print(dataset)


sys.path.append("/usr/lib64/python3.6/site-packages/")
import gfal2
from gfal2 import Gfal2Context, GError

gfal = Gfal2Context()

# Global variables definition : 

DEFAULT_ORIGIN_RSE = 'PIC-DET'
DEFAULT_SCOPE = 'test-root'

# Generate a random file : 

def generate_random_file(filename, size, copies = 1):
    """
    generate big binary file with the specified size in bytes
    :param filename: the filename
    :param size: the size in bytes
    :param copies: number of output files to generate
    
    """
    n_files = []
    n_files = np.array(n_files, dtype = np.float32)   
    for i in range(copies):
        file = filename + '-' + str(uuid.uuid4())
        if os.path.exists(file) : 
            print ("File %s already exist" %file)

        else:
            print ("File %s not exist" %file)    
            try : 
                newfile = open(file, "wb")
                newfile.seek(size)
                newfile.write(b"\0")
                newfile.close ()
                os.stat(file).st_size
                print('random file with size %f generated ok'%size)
                n_files = np.append(n_files, file)
            except :
                print('could not be generate file %s'%file)

    return(n_files)

list_files = generate_random_file('deletion', 10)     


if list_files :
    for n in range(0, len(list_files)) :
        
        client=Client()
        rulesClient=RuleClient()
        uploadClient=UploadClient()

        name_file = list_files[n]
        print(name_file)
    filePath="./"+name_file
    file = {'path': filePath, 'did_name':name_file, 'rse': DEFAULT_ORIGIN_RSE, 'did_scope': Default_Scope}

    # perform upload
    uploadClient.upload([file])


# In[4]:


did = list(client.list_replicas([{
            'scope': Default_Scope,
            'name': name_file
        }]))


print(json.dumps(did[0], indent=4, sort_keys=True))


# In[5]:


try: 
    get_meta = didc.get_metadata(scope=Default_Scope, name=name_file, plugin='ALL')
    for x in get_meta:
        print (x,':',get_meta[str(x)])
except: 
    print('no metadata associated to ', name_file)


# In[6]:


today = str(time.strftime('%Y%m%d')) 

set_meta = didc.set_metadata(scope=Default_Scope, name=name_file, key='night', value=today, recursive=False)
print(set_meta)


# In[7]:


get_meta = didc.get_metadata(scope=Default_Scope, name=name_file, plugin='ALL')

for x in get_meta:
    print (x,':',get_meta[str(x)])


# In[9]:


list_associated_meta = didc.list_dids_extended(scope=Default_Scope, filters={'night':today}, type='all', long=False, recursive=False)

print(list(list_associated_meta))


# In[ ]:




