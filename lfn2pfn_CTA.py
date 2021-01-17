"""
lfn2pfn.py

Default LFN-to-path algorithms for MAGIC
"""
import re
import os
import pathlib
from datetime import (
    datetime,
    tzinfo,
    timedelta,
    timezone,
)

############################
    
def look_for_run(fileName) :  

    try :
        run = re.search('\d{5}\.', fileName)
        if not run :
            run = re.search('_\d{5}', fileName)
            run = run[0].replace('_','')
        elif (type(run).__module__, type(run).__name__) == ('_sre', 'SRE_Match') : 
            run = run.group(0)
            run = run.replace('.','')
        else :
            run = run[0].replace('.','')         
        return(str(run))
    except : 
        pass
    
    try :
        if not run :
            run = re.findall('\d{5}\_', fileName)
            run = run[0].replace('_','')
        return(str(run))
    except : 
        pass

def look_for_date(fileName) :  

    try :
        date = re.findall('\d{8}', fileName)    
        return(str(date[0]))
    except : 
        pass

def look_for_type_files(fileName) :
    patterns_1 = ['dl1', 'dl2', 'muons_']
    
    matching_1 = [s for s in patterns_1 if s in fileName]
    if matching_1 :
        if matching_1[0] == 'muons_':
            matching_1 = ['dl1']
            
        matching = 'LST_' + str(matching_1[0]).upper()
    else : 
        matching = 'LST_RAW'
    
    return(str(matching))
############################

def groups(name_file) :
    organization = dict();
    

    
    f_name = os.path.basename(name_file)
    organization['replica'] = f_name.replace('+','_')
    organization['dataset_1'] = look_for_run(f_name)
    organization['container_1'] = look_for_date(name_file)    
    organization['container_2'] = look_for_type_files(name_file) 
    
    return(organization)
     

############################


if __name__ == '__main__':

    def test_magic_mapping(lfn):
        print(lfn)
        """Demonstrate the LFN->PFN mapping"""
        mapped_pfn = groups(name)
        print(mapped_pfn)
