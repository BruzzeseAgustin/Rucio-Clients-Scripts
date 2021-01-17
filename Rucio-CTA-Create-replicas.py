#!/usr/bin/env python
# coding: utf-8

# In[1]:


#!/usr/bin/python
# coding: utf-8

# In[1]:


from __future__ import absolute_import, division, print_function

__author__ = "Agustin Bruzzese"
__copyright__ = "Copyright (C) 2020 Agustin Bruzzese"

__revision__ = "$Id$"
__version__ = "0.2"

import sys
sys.path.append("/usr/lib64/python3.6/site-packages/")

import gfal2
import io
import json
import linecache
import logging
import numpy as np 
import os
import os.path
import random
import re
import time
import uuid
import zipfile
import string
import pathlib

from dateutil import parser
from datetime import (
    datetime,
    tzinfo,
    timedelta,
    timezone,
)
from gfal2 import (
    Gfal2Context,
    GError,
)
from io import StringIO

# Set Rucio virtual environment configuration 
os.environ['RUCIO_HOME']=os.path.expanduser('~/Rucio-v2/rucio')
from rucio.rse import rsemanager as rsemgr
from rucio.client.client import Client
from rucio.client.didclient import DIDClient
from rucio.client.replicaclient import ReplicaClient
import rucio.rse.rsemanager as rsemgr
# from rucio.client import RuleClient
from rucio.client.ruleclient import RuleClient

from rucio.common.exception import (AccountNotFound, Duplicate, RucioException, DuplicateRule, InvalidObject, DataIdentifierAlreadyExists, FileAlreadyExists, RucioException,
                                    AccessDenied)

from rucio.common.utils import adler32, detect_client_location, execute, generate_uuid, md5, send_trace, GLOBALLY_SUPPORTED_CHECKSUMS


gfal2.set_verbose(gfal2.verbose_level.debug)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
    
# ELIMINAR
def PrintException():
    import linecache
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))

# Configuration
account='root'
#auth_type='x509'

my_folder_test = 'CTA-test-v1'

# account=account, auth_type=auth_type
client = Client(account=account)

gfal = Gfal2Context()

# TASK PRIORITY SUPER LOW: mirar urlparse.urlunparse
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
        prefix = protocol['extended_attributes']['web_service_path'] + prefix
    url = schema + '://' + rucioserver
    if port != 0:
        url = url + ':' + str(port)
    rse_url = url + prefix
    
    return(rse_url)


# In[2]:


json_file = 'Rucio-data.json'

# Predifine origin RSE 
DEFAULT_ORIGIN_RSE = 'PIC-NON-DET'

# Use a predefine folder to create random data 
DEFAULT_PATH = os.path.join(get_rse_url(DEFAULT_ORIGIN_RSE), my_folder_test)

# Predifine scope
DEFAULT_SCOPE = 'test-root'

# Rucio settings 
rulesClient = RuleClient()

# Destiny RSEs
rses_catch = ['PIC-DET']

# Get list of all RSEs 
default_rses = list(client.list_rses())
rses_lists = []
for single_rse in default_rses :
    rses_lists.append(single_rse['rse'])
        
# Check if our test folder still exists 
gfal.mkdir_rec(DEFAULT_PATH, 775)


# In[2]:
print(DEFAULT_PATH)


# In[3]:


account='root'
auth_type='x509_proxy'

# account=account, auth_type=auth_type
CLIENT = Client(account=account)
didc = DIDClient(account=account)
repc = ReplicaClient(account=account)
rulesClient = RuleClient(account=account)
client = Client(account=account)
print(client.whoami())
print(client.ping())


# In[4]:



############################

# Check existence of file at RSE

############################

def check_replica(myscope, lfn, dest_rse=None):
    """
    Check if a replica of the given file at the site already exists.
    """
    if lfn : 
        replicas = list(
            client.list_replicas([{
                'scope': myscope,
                'name': lfn
            }], rse_expression=dest_rse))
        
        if replicas:
            for replica in replicas:
                if isinstance(replica,dict) :
                    if dest_rse in replica['rses']:
                        path = replica['rses'][dest_rse][0]
                        return(path)
        return(False)

    
############################

# Get UTC time
class simple_utc(tzinfo):
    def tzname(self,**kwargs):
        return "UTC"
    def utcoffset(self, dt):
        return timedelta(0)
    
def get_UTC_time() :
    dt_string = datetime.utcnow().replace(tzinfo=simple_utc()).isoformat()
    dt_string = str(parser.isoparse(dt_string))
    return(dt_string)

# Merge dictionary 
def Merge(dict1, dict2): 
    res = dict1.copy()   # start with x's keys and values
    res.update(dict2)    # modifies z with y's keys and values & returns None
    return(res)

# Generate random run
def generate_random() :
    return(random.randint(10000000,99999999))

# Get run from file
def look_for_run(fileName) :  

    try :
        run = re.search('\d{8}\.', fileName)
        if not run :
            run = re.search('_\d{8}', fileName)
            run = run[0].replace('_','')
        elif (type(run).__module__, type(run).__name__) == ('_sre', 'SRE_Match') : 
            run = run.group(0)
            run = run.replace('.','')
        else :
            run = run[0].replace('.','')
            
        return(run)
    except : 
        pass
    try :
        if not run :
            run = re.findall('\d{8}\_', fileName)
            run = run[0].replace('_','')
        return(run)
    except : 
        pass

def look_for_data(fileName) :
    fileName = fileName.replace('/','-')
    fileName = fileName.replace('_','-')
    
    try :
        date = re.search('\d{4}-\d{2}-\d{2}', fileName)
        date = datetime.strptime(date.group(), '%Y-%m-%d').date()
        return(str(date))
    except : 
        pass

    if not date :
        base, name = os.path.split(name_file)  

        file_name = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?]', name)

        date = datetime.strptime(file_name[0], "%Y%m%d").date()
        return(str(date))
# In[3]:


# In[5]:




# Upload previousl generated files via gfal at the base mouting point of the RSE PIC-INJECT
def event_callback(event):
    #print event
    print("[%s] %s %s %s" % (event.timestamp, event.domain, event.stage, event.description))


def monitor_callback(src, dst, average, instant, transferred, elapsed):
    print("[%4d] %.2fMB (%.2fKB/s)\r" % (elapsed, transferred / 1048576, average / 1024)),
    sys.stdout.flush()
    
# Set transfer parameters
params = gfal.transfer_parameters()
params.event_callback = event_callback
params.monitor_callback = monitor_callback
#params.checksum_check = True
params.set_checksum = True
params.overwrite = True
params.set_create_parent= True
params.get_create_parent= True 
# Five minutes timeout
params.timeout = 300


##############################

def make_dir(full_path) : 
    full_path = str(DEFAULT_PATH) + str(full_path)
    filename, file_extension = os.path.splitext(full_path)
    
    if '.root' in file_extension or '.gz' in file_extension or '.h5' or '.fz' or 'fits' :
        full_path, f_name = os.path.split(full_path) 
        gfal.mkdir_rec(full_path, 775)

        
    else :
        # Check if our test folder still exists 
        gfal.mkdir_rec(full_path, 775)

####################################

def make_file(f_name, dest, size = 60000000):
    newfile = open(f_name, "wb")
    newfile.seek(size)
    newfile.write(b"\0")
    newfile.close ()




def make_folder_file(path, DestRSE) :
    
    # Try to build path + file 
    if path is not None : 
        full_path = str(DEFAULT_PATH) + str(path)
        full_path, f_name = os.path.split(full_path)
        make_file(f_name, full_path)
        
        dir_name = make_dir(path)

        try :
            cur_dir = os.getcwd()
            source = os.path.join(cur_dir, f_name)
            r = gfal.filecopy(params, 'file:///'+source, os.path.join(full_path,f_name))
            os.remove(f_name)
            
            return(path)
        
        except Exception as e:
            print("Copy failed: %s" % str(e))
            os.remove(f_name)
    else : 
        path = random_line(filename, DestRSE)
        
        if isinstance(path , list):
            path = path[0]
            
        path = make_folder_file(path)
        return(path)

# function to add to JSON 
def write_json(data, filename=json_file): 
    with io.open(filename, 'w') as f: 
        json.dump(data, f, ensure_ascii=False, indent=4)


# In[4]:


# In[6]:



def random_line(filename, DestRSE, number=1, list_files=None):
    
    lines = open(filename).read().splitlines()
    
    if list_files == None :
        my_list = []
        
    else :
        print('this is list of file ', list_files)
        my_list = list_files
            
    for n in range(number) :  
        
        myline = random.choice(lines)
        f_name = os.path.basename(myline)

        run = str(look_for_run(myline))
        new_run = str(generate_random())
        myline = myline.replace(run,new_run)

        # 2) If it is registered, skip add replica 
        check = check_replica(myscope=DEFAULT_SCOPE, lfn=f_name.strip('+').replace('+','_'), dest_rse=DestRSE) 
        
        # If file dont exists in destiny RSE
        if check != False : 
            run = str(look_for_run(myline))
            new_run = str(generate_random())

            myline = myline.replace(run,new_run)     
        
        if isinstance(myline, list):
            my_list.extend(myline)  
            
        else :
            my_list.append(myline)   
    
    while len(my_list) < number:
        myline = random_line(filename, DestRSE, number, my_list)
        
        if isinstance(myline, list):
            my_list.extend(myline)
        else :
            my_list.append(myline) 
            
    my_list = np.unique(my_list)       
    return(my_list) 


######################################################
filename = 'CTA-LST.txt'

for rses in rses_catch: 
           
    # Generate dummy random files at PIC-INJECT  
    all_path = random_line(filename, rses, number=24)
    
    #print(rses, all_path, 'this is list', len(all_path))
    print(rses, 'this is list', len(all_path))
    i = 1
    for x in range(len(all_path)) :
        path = all_path[x]
        print(path)
        
        try :
            un = re.findall('\d{8}', path)
            
            runs = re.findall('\d{4}\.', path)
            
            for run in runs : 
                new_run = str(random.randint(1000,9999))+'.' 
                path = path.replace(run, new_run)
            
            import time
            from datetime import date  
            today = str(time.strftime('%Y%m%d'))
            
            replace = os.path.join('/',path.replace(un[0], today))
            
            print(str(i) + ' ' +  str(path) + ' ' + replace)
             
            path = make_folder_file(replace, rses)        

            i = i + 1         

            rse_path = os.path.join(DEFAULT_PATH), str(replace)
            print(rse_path)
            full_path, f_name = os.path.split(path)

        except :
            PrintException()


# In[ ]:




