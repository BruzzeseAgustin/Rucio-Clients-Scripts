#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Immport libraries 

from __future__ import absolute_import, division, print_function

import sys,os,os.path

import graphyte, socket

# Set Rucio virtual environment configuration 

os.environ['RUCIO_HOME']=os.path.expanduser('~/rucio')

# Import Rucio libraries
from pprint import pprint

import json
import math
import re
import time
import os
import sys
import numpy as np 
#import hashlib

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
#import hashlib
import uuid 

from itertools import islice
from subprocess import PIPE, Popen
import requests
from requests.exceptions import ReadTimeout


try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3
import linecache

sys.path.append("/usr/lib64/python3.6/site-packages/")
import gfal2
from gfal2 import Gfal2Context, GError
gfal2.set_verbose(gfal2.verbose_level.debug)

gfal = Gfal2Context()


# In[2]:


# Destination = 'gsiftp://grid2.magic.iac.es:2811//data/Other/rucio_tmp/Server-test'
import rucio.rse.rsemanager as rsemgr

# Rucio settings 

account='root'
auth_type='x509_proxy'

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
    #print(rse_url)
    return(rse_url)

# Predifine origin RSE 
DEFAULT_ORIGIN_RSE = 'ORM-NON-DET'

# Use a predefine folder to create random data 
DEFAULT_PATH = os.path.join(get_rse_url(DEFAULT_ORIGIN_RSE), 'Server-test')

print(DEFAULT_PATH)


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

    # print("*-Listin files from url : %s" % dir_path)
    all_files = []

    # Itinerate over all the entries  
    listFiles = gfal.listdir(str(dir_path))
    for file in [x for x in listFiles if x != '.' if x != '..']:
    #for file in listFiles :
        # Create full Path 
        fullPath = os.path.join(dir_path, file)
        #print('|-- '+ fullPath)
        is_dir = check_directory(fullPath) 
        # If entry is a directory then get the list of files in
        if is_dir == True :
            all_files = all_files + scrap_through_dir(fullPath)

        else :
            all_files.append(fullPath) 
            
    return(all_files)
                                                                        
def scrap_through_files(dir_path) : 

    #print("*-Listin files from url : %s" % dir_path)
    all_files = []

    # Itinerate over all the entries  
    listFiles = gfal.listdir(str(dir_path))
    #for file in listFiles :
    for file in [x for x in listFiles if x != '.' if x != '..']:

        # Create full Path 
        fullPath = os.path.join(dir_path, file)
        #print('|-- '+ fullPath)
        is_dir = check_directory(fullPath) 
        # If entry is a directory then get the list of files in
        if is_dir == True :
            pass

        else :
            all_files.append(fullPath) 
            
    return(all_files)


# In[6]:


# Load grafan configuration for PIC

gr_prefix = [line for line in open('/etc/collectd.d/write_graphite-config.conf', 'r').readlines() if "Prefix" in line][0].strip().split()[1].strip('"')

def prepare_grafana(dictionary, string='RUCIOPIC.') :
    metric_list = []
    for key in dictionary.keys() :
        if isinstance(dictionary[key],int):
            print(str(string+key), dictionary[key])
            metric_list.append((str(string+key),dictionary[key]) )

        elif isinstance(dictionary[key],dict):
            print(prepare_grafana(dictionary[key], str(string+key+'.')))
            metric_list.extend(prepare_grafana(dictionary[key], str(string+key+'.')))       
    return(metric_list)

def send_to_graf(dictionary, myport=2013, myprotocol='udp') : 
    for key in prepare_grafana(dictionary):
        if (key[0], key[1]) is not None : 
            print(key[0].lower(),key[1])
            graphyte.Sender('graphite01.pic.es', port=myport, protocol=myprotocol, prefix=gr_prefix + socket.gethostname().replace(".","_")).send(key[0].lower(), key[1])
            graphyte.Sender('graphite02.pic.es', port=myport, protocol=myprotocol, prefix=gr_prefix + socket.gethostname().replace(".","_")).send(key[0].lower(), key[1])


# In[11]:


### Look for all files at the Origin RSE (see DEFAULT PATH)
listOfFiles = scrap_through_dir(DEFAULT_PATH)
print()


# print(len(listOfFiles))

REPLICAS = dict()
REPLICAS['COUNT_RSE'] = {}
REPLICAS['COUNT_RSE'][DEFAULT_ORIGIN_RSE] = len(listOfFiles)

send_to_graf(REPLICAS)


# In[ ]:




