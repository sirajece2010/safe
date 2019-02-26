# -*- coding: utf-8 -*-
'''
    File name: libKPI.py
    Author: Sunil S
    Date created: 29/06/2018
    Python Version: 3.6
'''

import re
import pexpect
import sys
import os
import config
from time import sleep
import datetime
import pandas as pd
import numpy as np
import subprocess as sp
from functools import reduce
import string
import matplotlib.pyplot as plt
import csv
import subprocess
import libRSE
#from datetime import datetime
#from dateutil import tz

_HEXDUMP = None
_HOME = None


df=0
df=pd.DataFrame(index=[], columns=[])
df1=0
df1=pd.DataFrame(index=[], columns=[])

def obu_run_command(child, cmd, *args):
    try:
        command = None
        if re.search(r"obu", cmd, re.I):
            cmd1 = cmd.split("obu")[1].strip()
            command = cmd1
        else:
            command = cmd
        if len(args) != 0:
            cmd1 = command
            for arg in args:
                cmd1 = cmd1 + " " + arg
            command = cmd1
        print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("{}".format(command))
        child.expect(config.OBUPMT, timeout=500)
        data = child.before
        data = str(data, "utf-8")
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened while executing \"{}\"".format(command))
        return None

def bsmd_rv_simulation(child, cmd, x, boards):
    global num_of_rvs
    y1= int(boards)
    x1= int(x)
    x2= float(x1/y1) 
    num_of_rvs = float(x2)
    print(num_of_rvs)
    y= float(100/num_of_rvs)
    print(y)
    cmd= 'BSMd -i /etc/config/ -N' + ' ' + str(num_of_rvs) + ' ' + '-T' + ' ' + str(y) + ' ' + '-P 2 -D 0 -R 8 &'
    command = cmd
    print("OBU command:{}".format(command))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    sleep(2)
    child.expect(config.OBUPMT, timeout=500)
    data = child.before
    data = str(data, "utf-8")
    return data

def cpu_log(child, cmd, rv_count):
    cmd = 'top -d 1 -n 120' + ' > ' + '/tmp/' + str(rv_count) + '.log'
    command = cmd
    print("top command:{}".format(command))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT, timeout=500)
    data = child.before
    sleep(120)
    data = str(data, "utf-8")
    return data



#Check the packet count as per specified range.
def diff_fun(cmd, val1, val2, rvs):
    print(val1)
    print(val2)
    val11 = float(val1)
    print(val11)
    val22 = float(val2)
    print(val22)
    rv1s = float(rvs)
    result = float((val22-val11)/120)
    print ("Average BSM count(taken for 2 min):", float(result))
    if result > ((rv1s*(10))-35) and result < ((rv1s*(10))+40):
         return 1
    else:
         return 0

#copies the cpu usage logs onto the test PC.
def pobu_file_copy(child ,cmd ,x):
    file_name = '/tmp/' + str(x) + '.log'
    print(file_name)
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("scp {0} {1}@{2}:{3}/logs/kpi/".format(
        file_name, config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH))
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        return 1
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        return 1

#rv_file_copy copies the pre-recorded files from the test PC to the ASD.
def rv_file_copy(child ,cmd ,x ,y):
    file_name = str(x) 
    print(file_name)
    dest_path = str(y)
    print(dest_path) 
    child.sendline(" ")
    child.expect(config.OBUPMT)
    child.sendline("scp {1}@{2}:{3}/resource/kpi/{0} {4}".format(
        file_name, config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH, dest_path))
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        return 1
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        return 1


#Gets interface logs for specified interface.
def if_stats(child, cmd, *args): 
    interface = args[0] 
    print(interface) 
    stat_check = args[1] 
    print(stat_check)  
    command1 = 'ifconfig ' + str(interface) + ' | '+ ' grep ' + "'" + str(stat_check) + "'" + '| cut -d: -f2 | cut -d" " -f1' 
    print(command1)
    print("command is:{}".format(command1))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command1))
    child.expect(config.OBUPMT, timeout=500)
    child.sendline("{}".format(command1))
    child.expect(config.OBUPMT, timeout=500)
    data = child.before
    data = str(data, "utf-8")
    print(data)
    output = data.split('\n')
    values = output[1]
    return values

#Extracts the string (for config check) from a config file. 
def pstr_ext(child, cmd, path, param, pos):
    cmd = str(cmd)
    path = str(path)
    param = str(param)
    pos = str(pos)
    command = 'cat ' + path + '|' + 'grep -w ' + param + "|awk '{print $" + pos + "}'"
    print(command)
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT, timeout=500)
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT, timeout=500)
    data = child.before
    data = str(data, "utf-8")
    print(data)
    output = data.split('\n')
    values = output[2]
    values = values.replace(';','')
    values = values.strip()    
    return values

#Run and log cpu usage using mpstat.
def mp_stat(child, cmd, mp_interval, mp_iter, mp_path, mp_file):
    mp_interval = str(mp_interval)
    mp_iter = str(mp_iter)
    print(mp_iter)
    mp_path = str(mp_path)
    print(mp_path)
    mp_file = str(mp_file)
    print(mp_file)
    cmd1 = 'mpstat ' + str(mp_interval) + ' '+ str(mp_iter) + ' -P ALL' + '> /' + str(mp_path) + '/' + 'mp' + str(mp_file) + '.log'
    print(cmd1)
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(cmd1))
    child.expect(config.OBUPMT, timeout=500)

    #file_converter calculates the avg cpu usage and logs the same onto a csv file. 
def file_converter(a, b, c, d):
    i = 1  # 'i' is the total number of lines or iterations of the log file.
    x = 0  #initialization for the temporary sum holder.
    c = int(c)   # 'c' indicates the position of the usage print in a line with respect to each parameter like bsm,idle etc.
    dest_path = ("{2}/logs/kpi/all_log/".format(config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH))
    src_path = ("{2}/logs/kpi/".format(config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH))
    z = str(src_path) + str(b) + '.log' # 'b' represents the rv count. 
    print(z)
    y1 = str(a) # 'a' represents the parameter with respect to which the cpu usage has to be calculated.
    print(y1)
    my_regex = ".*" + re.escape(y1) + ".*"   # term to search for the in the log parameter eg)bsmd,idle etc.
    inp = open(z, "r")
    for line in inp:
        if re.match(my_regex, line):
            print(line)
            text = re.split(r'%', line)
            print(text)
            y = re.search(r'\d+', text[c]).group()
            df1.loc[ i, a] = y
            df1.to_csv(dest_path + str(b) +'.csv', sep=',')
            x = x + int(y)    #
            print(x)   # x represents the sum of cpu value with respect to a search field eg)bsmd,idle etc.
            z = x/i
            i = i + 1  # i is the count for the instance of the search parameter eg)bsmd,idle etc.
    df.loc[ b, a] = z
    print(df)
    df.to_csv(dest_path + 'main.csv', sep=',')



#Merge  2csv files
def csv_merge(x,y):
    file1_df = 0
    file2_df = 0
    src_path = ("{0}/logs/kpi/".format(config.SAFE_FW_PATH))
    dest_path = ("{0}/logs/kpi/".format(config.SAFE_FW_PATH))
    x1 = str(src_path) + str(x) # 'x' is the 1st file that has to be merged
    y1 = str(src_path) + str(y) # 'y' is the 2nd file that has to be merged
    file1_df = pd.read_csv(x1,keep_default_na=False, na_values=[""])
    file2_df = pd.read_csv(y1,keep_default_na=False, na_values=[""])
    file1_sub = file1_df.head(10)
    file2_sub = file2_df.head(10)
    file4_stack = pd.concat([file1_sub, file2_sub], axis=1)
    file4_stack.to_csv(dest_path + 'output.csv', index=False)


#Print robot framework output to a file.
def rb_print(x,y):
    y = str(y)
    print (x)
    #x = float(x)
    file_path = ("{0}/logs/kpi/all_log/".format(config.SAFE_FW_PATH)) 
    file_name = str(file_path) + str(y)
    with open(file_name, 'a') as file:
        file.write(str(x) + '\n')

#Clear file contents.
#Print robot framework output to a file.
def clr_file(*args):
    file_name = str(args[1])
    file_path = str(args[0])
    file_name = str(file_path) + str(file_name)
    f = open(file_name, 'w') 
    f.close()


def get_from_dict(var_dict, dev_key):
        dev_key = str(dev_key)
        dict_name = str(var_dict)
        print (dict_name) 
        var_dict1 = config.OBU_kpi[dev_key]
        print (var_dict1)
        return var_dict1
    
def get_val_from_dict(child, cmd, var_dict, dev_key):
        key = str(dev_key)
        dict_name = str(var_dict)
        print (dict_name)
        var_dict1 = getattr(config,dict_name)[key]
        print (var_dict1)
        return var_dict1


def utc_2_local(ut_time):
    ut_time = str(ut_time)
    # Auto-detect zones:
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()
    # utc = datetime.utcnow()
    utc = datetime.strptime(ut_time, '%d/%m/%Y-%H:%M:%S')
    # Tell the datetime object that it's in UTC time zone since 
    # datetime objects are 'naive' by default
    utc = utc.replace(tzinfo=from_zone)
    # Convert time zone
    central = utc.astimezone(to_zone)
    return central

#Extracts average data from mpstat log.
def mp_extr(file_path, filtr, val_pos):
        file_path = str(file_path) + '.log'
        filtr = str(filtr)
        val_pos = str(val_pos)
        cmd = 'cat ' + file_path + ' |' +' grep ' + "'" + filtr + "' " + '| awk ' + "'{print " + val_pos + "}'"
        print(cmd)
        result = subprocess.check_output(cmd, shell=True) 
        print(result)
        return str(result, "utf-8")

#DMIPS converter.
def dmips_conv(*args):
    file_path = str(args[0]) + str(args[1])
    #dest_file_path = str(args[0]) + 'dmain.csv'
    header = str(args[2])
    total_dmips = int(args[3])
    header_new = header + '_dmips'
    df = pd.read_csv(file_path)
    df[header_new] = (df[header]) * (total_dmips/100)
    df.to_csv(file_path, sep=',', index=False)

def csv_plotter(src_path,file_name,dest_path,dest_file_name,ref_plot,*args):
    #Here args represents all the plot variables that are to be selected from the csv files.
    src_file= str(src_path) + str(file_name)  #src csv files absolute path.
    dest_file= str(dest_path) + str(dest_file_name) #destination plots absolute path.
    f=pd.read_csv(src_file)
    keep_col = [*args]
    tmp_f = f[keep_col]
    ref_plot = str(ref_plot)
    print(ref_plot)
    tmp_f.columns.values[0]=ref_plot
    tmp_f.head()
    tmp_f.plot(x=ref_plot)
    plt.savefig(dest_file)


def kpi_nequal(output, value, index=None):
    if index is None:
        return int(str(output) != str(value))
    else:
        return int(str(output[str(index)]) != str(value))


#Converts idle cpu usage to actual cpu usage.
def idle_to_usage(*args):
    file_path = str(args[0]) + str(args[1])
    #dest_file_path = str(args[0]) + 'dmain.csv'
    header = 'idle'
    header_new ='usage'
    df = pd.read_csv(file_path)
    df[header] = 100 - (df[header])
    #df.columns.values[1]='total cpu usage'
    #Renames the 1st colulmn on the log file to Rv count.
    #df.columns.values[0]='RV count'
    df.to_csv(file_path, sep=',', index=False)

def idle_to_used(*args):
    file_path = str(args[0]) + str(args[1])
    header = args[2]
    print(header)
    new_header = args[3]
    print(new_header)
    df = pd.read_csv(file_path)
    df[new_header] = 100 - (df[header])
    df.to_csv(file_path, sep=',', index=False)

#Renames csv file header.
def csv_header(*args):
   file_path = str(args[0]) + str(args[1])
   new_header = str(args[3])
   header_pos = int(args[2])
   df = pd.read_csv(file_path)
   df.columns.values[header_pos] = new_header
   df.to_csv(file_path, sep=',', index=False)

#Adding columns elements from a csv file.(This is custom made for only 3 variables)
def csv_adder(*args):
    file_path = str(args[0]) + str(args[1])
    new_header = args[2]
    header_1 = args[3]
    header_2 = args[4]
    header_3 = args[5]
    print(new_header)
    df = pd.read_csv(file_path)
    df[new_header] = (df[header_1]) + (df[header_2]) + (df[header_3])
    df.to_csv(file_path, sep=',', index=False)

#Create a csv file from a parent csv file by selecting respective headers.
#def csv_to_csv(src_path,src_file_name,,dest_file_name,*args):
#    f=pd.read_csv("/home/savari/Desktop/temp_auto/Automation/safe/logs/kpi/main.csv")
#    keep_col = [*args]
#    new_f = f[keep_col]
#    new_f.to_csv("/home/savari/Desktop/temp_auto/Automation/safe/logs/kpi/newFile.csv", index=False)

def obu_get_latency_average(child, cmd, *args):
    if len(args) > 1:
        try:
            file_name = args[0]
            start_param = args[1]
            end_param = args[2]
        except IndexError:
            return "Provide required params"
    else:
        return "provide params"
    child.sendline("")
    child.expect(config.OBUPMT)
    dest_path = "resource/files/"
    # copying file from
    obu_scp(child, "obu scp", file_name, dest_path)
    path = os.path.abspath(config.SAFE_FW_PATH)
    file_path = "{0}/resource/files".format(path)
    file_name = os.path.basename(file_name)
    print("FILE_NAME:{}".format(file_name))

    def convert_time_nanosecs(time_str):
        time_search = re.search(r"(\d+):(\d+)", time_str)
        secs = time_search.group(1)
        nanosecs = time_search.group(2)
        return int(secs) * 10 ** 9 + int(nanosecs)

    try:
        if file_name not in os.listdir(file_path):
            print("input file is missing")
            return -1
    except:
        print("Path is not valid")
        return -1
    with open("{}/{}".format(file_path, file_name), 'r') as f:
        test_string = f.read()
    try:
        # below two parametrs gives the time string
        start_param_list = re.findall(
            r"ts\s([\d:]*)::.*{}".format(start_param), test_string)
        end_param_list = re.findall(
            r"ts\s([\d:]*)::.*{}".format(end_param), test_string)
    except IndexError:
        print("No time string found")
        return -1
    if abs(len(end_param_list)-len(start_param_list)) ==1:
        if len(end_param_list) > len(start_param_list):
            end_param_list.pop(0)
        else:
            start_param_list.pop()
    start_time_in_nsec = map(convert_time_nanosecs, start_param_list)
    end_time_in_nsec = map(convert_time_nanosecs, end_param_list)

    start_end_diff_time = [end-start for start, end in zip(start_time_in_nsec,
                                                           end_time_in_nsec)]
    try:
        Avg = round(sum(start_end_diff_time) / len(start_end_diff_time), 4)
        return Avg
    except ZeroDivisionError:
        print("Start param/End param missing in latency file")
        return -1


def get_timestamp_from_file(child,cmd,*args,index_to_change=1,option=None):

    if len(args) >= 1:
        try:
            file_name = args[0]
        except IndexError:
            return "Provide required params"
    else:
        return "provide params"
    if index_to_change >= 1:
        index_to_change-=1
    child.sendline("")
    child.expect(config.OBUPMT)
    path = os.path.abspath(config.SAFE_FW_PATH)
    file_path = "{0}/resource/files".format(path)
    file_name = os.path.basename(file_name)
    print("FILE_NAME:{}".format(file_name))
    with open("{}/{}".format(file_path, file_name), 'r') as f:
        test_string = f.read()

    time_list = re.findall(r"([\d]{2}:[\d]{2}:[\d]{2})", test_string)
    return_dict={"timestamp_at_index":time_list[index_to_change],"length":len(time_list)}
    if option:
        try:
            return return_dict[option]
        except KeyError:
            print("Option is not provided.")
            return None
    
    return return_dict["timestamp_at_index"]
'''    try:
        return time_list[index_to_change]
    except IndexError:
        print("Provide valid index to find")'''

        
def rsu_cpu_usage_log(child, cmd):
    cmd = 'top -d 1 -n 120' + ' > ' + '/tmp/cpu_usage.log'
    command = cmd
    print("top command:{}".format(command))
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline("{}".format(command))
    child.expect(config.SHELLPMT, timeout=500)
    data = child.before
    sleep(120)
    libRSE.file_copy(child, '/tmp/cpu_usage.log')    
    data = str(data, "utf-8")
    return data

def obu_cpu_usage_log(child, cmd):
    cmd = 'top -d 1 -n 120' + ' > ' + '/tmp/obu_cpu_usage.log'
    command = cmd
    print("top command:{}".format(command))
    child.sendline("")
    child.expect(config.EUOBUPMT)
    child.sendline("{}".format(command))
    child.expect(config.EUOBUPMT, timeout=200)
    data = child.before
    sleep(130)
    #libRSE.obu_scp(child, '/tmp/obu_cpu_usage.log', 'resource/files')    
    data = str(data, "utf-8")
    return data

def run_pwr_switch_command(child,cmd,switch=None,status=None,port=None):

    if status and switch and port is None:
        print("Provide all necessary arguments")
        return None
    try:
        wps_dict=config.WPS_Dict[switch]
        ping_output = subprocess.check_output(f'ping {wps_dict["WPS_HOSTIP"]} -c 5', stderr=subprocess.STDOUT, shell=True)
    except KeyError:
        print(f"Provide WPS dict info in config file for {switch}")
        return None

    if re.search(r"0% packet loss", ping_output.decode()) is None:
        print("web power switch host is not reachable")
        return None
    # print("wget --no-proxy -O /dev/null -q --auth-no-challenge 'http://{WPS_UNAME}:{WPS_PASSWORD}@{WPS_HOSTIP}/outlet?'{0}'={1}'".format(port,status,**wps_dict))
    command="wget --no-proxy -O /dev/null -q --auth-no-challenge 'http://{WPS_UNAME}:{WPS_PASSWORD}@{WPS_HOSTIP}/outlet?'{0}'={1}'".format(port,status,**wps_dict)
    subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
    return 1



