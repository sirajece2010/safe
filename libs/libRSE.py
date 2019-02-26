# -*- coding: utf-8 -*-
'''
    File name: libRSE.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''

import re
import pexpect
import sys
import os
import config
from time import sleep
from time import time as get_time
import time
import datetime
import dateutil
import pandas as pd
import numpy as np
import subprocess as sp
from functools import reduce
import wsmpHead
import pickle
import etsihead
import logging
import json
import requests
import pyshark
import traceback

_HEXDUMP = None
_HOME = os.getenv("HOME")
dev_conct_dict = None  # We  init this dict in start_of_testcase func
_logger_libRSE = logging
_file_handler_libRSE = None
_counter = 0
TESTCASE_ID = None  # Used to store .txt file name e.x obu_01.txt.
TC_DASHBOARD_VARS = None
# This Dictionary is used while filing bugs(Automation) in case of test case failure.
# Keys holds the names of the logs.
FAILURE_LOGS_VARS = {
    "tcid_log_dir": None,  # Below logs go into this dir.
    "syslogs": None,
    "dmesg": None,
    "ps": None
}

# This Dict object used to map Jira project names to their respectieve ID.
JIRA_PROJECT_NAME_TO_ID = {
    # "NAD": 10501,
    # "OM": 11303,
    # "DEL": 11401,
    # "TOOL": 11402,
    # "QT": 11403,
    # "SE": 11404,
    "Safe-test": 11420,
    "SW1000": 10700,
    # "PS": 11405,
    # "SH": 11406,
    # "CUST": 10800,
    # "RIGTOOL": 11408,
    # "MRA": 11410,
    # "DVS": 11411,
    # "MSM": 11412,
    # "UR": 10900,
    # "MI": 11413,
    # "HP": 11414,
    # "OTE": 11415,
    # "MP": 11416,
    # "MEC": 11417,
    "MW1000": 11001,
    # "EM": 11418,
    # "AT": 11100
}

JIRA_ISSUE_NAME_TO_ID = {
    "Risk": 10200,
    "Feature Enhancements": 10705,
    "Feature": 10201,
    "Order": 10500,
    "Bug": 10103,
    "New Feature": 10202,
    "Task": 10101,
    "Story": 10701,
    "Improvement": 10600,
    "Sub-task": 10102,
    "Epic": 10000,
    "Requirement": 10700,
    "Story": 10100,
    "Task": 10704,
}

TC_ATTRIBUTES_DICT = {
    # description: This var is set by autogen.py while parsing .txt to .robot.
    # bug_id: This specfies if tc is related to bug, feature, issue etc.
    # logs: Currently we are not using it. We get this info by FAILURE_LOGS_VARS dict.
    # path_to_logs: set by file_backup_func API in genLIB
    "project_id": None,
    "issue_id": None,
    "jira_id": None,
    "logs": None,
    "description": None,
    "path to logs": None
}

HEALTH_CHECK_DICT = None  # Stores as {"OBU1": HEALTH_CHECK_VARS}
HEALTH_CHECK_VARS = None

TC_START_END_TIME = {
    "start_time": "NA",
    "end_time": "NA"
}

TC_DEVICE_BUILD_NUM = {
    "rsu": "NA",
    "obu": "NA",
    "euobu": "NA"
}


def tc_db_vars_init():
    # this data being used to update the SAFE DashBoard
    global TC_DASHBOARD_VARS
    TC_DASHBOARD_VARS = {
        "tc_id": "NA",  # TL-ID or JIRA-ID
        "build_name": "NA",
        "build_num": "NA",
        "test_name": "NA",
        "test_source": "NA",  # testlink or jira
        "test_type": "NA",
        "component": "NA",
        "standard": "NA",
        "stack": "NA",
        "product": "NA",
        "software": "NA",
        "test_result": "NA",  # This var is being set in check status in case of fail
        "date_time": "NA",
        "test_duration": "NA",
        "release_num": "NA",
        "logs_folder": "NA"  # This var is being set in file_backup_func
    }

# This function is being called at the start of the testcase


def fill_tc_dashboard_var1(tc_name):
    global TC_DASHBOARD_VARS
    tc_db_vars_init()  # Init TC_DASHBOARD_VARS Dict
    TC_START_END_TIME["start_time"] = get_time()
    testcase_name = re.sub(r"\.txt", "", tc_name)
    if re.search(r"rsu", testcase_name):
        TC_DASHBOARD_VARS["build_name"] = "RSU_SW1000_6.1.99"
    else:
        TC_DASHBOARD_VARS["build_name"] = "ASD_MW1000_6.1.99"
    TC_DASHBOARD_VARS["test_name"] = testcase_name
    TC_DASHBOARD_VARS["test_source"] = "jira" if re.search(
        r"jira", testcase_name, re.I) else "testlink"
    TC_DASHBOARD_VARS["test_type"] = "Functional"
    TC_DASHBOARD_VARS["component"] = "BSM"
    TC_DASHBOARD_VARS["standard"] = "1609.3" if re.search(
        "euobu", tc_name, re.I) else "1609.3"
    TC_DASHBOARD_VARS["stack"] = "wave" if re.search(
        "obu", tc_name) else "etsi"
    TC_DASHBOARD_VARS["release_num"] = "6.9.1"
    TC_DASHBOARD_VARS["software"] = "NA"
    return

# This function is being called at the end of test case


def fill_tc_dashboard_var2(test_result=True, db_str=None):
    safe_fw_path = config.SAFE_FW_PATH
    TC_START_END_TIME["end_time"] = get_time()
    dt_now = datetime.datetime.now()
    dt_format = "{}-{}-{} {}:{}:{}".format(
        dt_now.day, dt_now.month, dt_now.year, dt_now.hour, dt_now.minute, dt_now.second)
    TC_DASHBOARD_VARS["date_time"] = dt_format
    test_duration = TC_START_END_TIME["start_time"] - \
        TC_START_END_TIME["end_time"]
    TC_DASHBOARD_VARS["test_duration"] = str(test_duration)
    if not test_result:
        TC_DASHBOARD_VARS["test_result"] = "fail"
    else:
        TC_DASHBOARD_VARS["test_result"] = "pass"
    db_keys = ["tc_id", "build_name", "build_no", "test_name", "test_source", "test_type", "component", "standard", "stack", "product",
               "software", "test_result", "date_time", "test_duration", "release_num", "logs_folder"]
    # if not db_str:
    # To access TC_ATTRIBUTE_DICT we have to fill it first
    #    jira_attributes_func()
    if TC_ATTRIBUTES_DICT["jira_id"]:
        temp_var = re.sub("#Automated:", "", TC_ATTRIBUTES_DICT["jira_id"])
        TC_DASHBOARD_VARS["tc_id"] = temp_var
    else:
        TC_DASHBOARD_VARS["tc_id"] = TC_DASHBOARD_VARS["test_name"]
    try:
        web_data = requests.get('https://build.savari.net/job/Automation/job/\
{0}/api/xml/?xpath=//*/build[1]'.format(TC_DASHBOARD_VARS["build_name"]),
                                auth=('savari-ci', '9+1k+.6)98OI14q'), verify=False)
    except ConnectionError:
        return -1
    try:
        build_num = re.search(
            b"<number>([\d]+)</number>", web_data.content, re.I).group(1)
        TC_DASHBOARD_VARS["build_num"] = str(build_num, "utf-8")
    except AttributeError:
        print("No build num found. Getting build num from cat /etc/banner")
    db_keys = [
        "tc_id", "build_name", "build_num",
        "test_name", "test_source", "test_type",
        "component", "standard", "stack", "product",
        "software", "test_result", "date_time",
        "test_duration", "release_num", "logs_folder"
    ]
    db_val = [TC_DASHBOARD_VARS[key] for key in db_keys]
    # pushing the db str to the database
    db_str = ",".join(db_val)
    os.chdir("{}/dashboardClientDeploy/".format(safe_fw_path))
    db_cmd = "java -jar DashboardClient1.0.jar \"{}\"".format(db_str)
    print(db_cmd)
    os.system(db_cmd)
    os.chdir("{}/".format(safe_fw_path))
    return


def start_of_testcase(tc_name):
    global dev_conct_dict
    dev_conct_dict = dict()
    fill_tc_dashboard_var1(tc_name)
    return 1

# This function is being called at the end of the testcase


def end_of_testcase(test_result=True, db_str=None):
    try:
        fill_tc_dashboard_var2(True)
    except:
        print("Exception while adding testcase data to dashboard data base")
        print(traceback.format_exc())
    closing_connections()
    return db_str


def closing_connections(device=None):
    global dev_conct_dict
    child_keys = dev_conct_dict.keys()
    try:
        if re.search("(IUT)|(COC)", device, re.I):
            coc_killall(device)
    except Exception:
        print(traceback.format_exc())
        print("Exception while killing coc_tcia")
        print("Please check if it is properly killed in following testcase")
    for key in child_keys:
        print("KEY:", key)
        child = dev_conct_dict[key]
        if child.isalive():
            child.close(force=True)
            #libRSE.child_close(child, "child close", key)
            print("child is closed with key {}:{}".format(key, child))
    return


def env_setup():
    global _HOME
    _HOME = os.getenv("HOME")
    if not os.path.exists("{}/SAFElogs".format(_HOME)):
        os.mkdir("{}/SAFElogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/bsmlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/bsmlogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/nojournal/".format(_HOME)):
            os.mkdir("{}/SAFElogs/nojournal/".format(_HOME))
        if not os.path.exists("{}/SAFElogs/camlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/camlogs".format(_HOME))
    else:
        if not os.path.exists("{}/SAFElogs/bsmlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/bsmlogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/nojournal/".format(_HOME)):
            os.mkdir("{}/SAFElogs/nojournal/".format(_HOME))
        if not os.path.exists("{}/SAFElogs/camlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/camlogs".format(_HOME))
    return 1


def jira_attributes_func(description="NA"):
    global TC_ATTRIBUTES_DICT, TESTCASE_ID
    # "11420" is temporary project id. Will move back to the actual ones.
    if re.search(r"^rsu", TESTCASE_ID, re.I):
       # TC_ATTRIBUTES_DICT["project_id"] = str(
       #     JIRA_PROJECT_NAME_TO_ID["SW1000"])
        TC_ATTRIBUTES_DICT["project_id"] = "11420"
    elif re.search(r"^obu", TESTCASE_ID, re.I):
       # TC_ATTRIBUTES_DICT["project_id"] = str(
       #     JIRA_PROJECT_NAME_TO_ID["MW1000"])
        TC_ATTRIBUTES_DICT["project_id"] = "11420"
    elif re.search(r"^euobu", TESTCASE_ID, re.I):
       # TC_ATTRIBUTES_DICT["project_id"] = str(
       #     JIRA_PROJECT_NAME_TO_ID["MW1000"])
        TC_ATTRIBUTES_DICT["project_id"] = "11420"
    try:
        jira_id = re.search(r"^([\w_\-\s]+):", description).group(1)
        jira_id = jira_id.strip()
        if re.search("TL", jira_id):
            jira_id = "#Automated:{}".format(jira_id)
    except AttributeError:
        print('No jira ID found')
        jira_id = None
    TC_ATTRIBUTES_DICT["issue_id"] = str(JIRA_ISSUE_NAME_TO_ID["Bug"])
    TC_ATTRIBUTES_DICT["jira_id"] = str(jira_id)
    TC_ATTRIBUTES_DICT["description"] = description
    return 1


def health_check_var_init():
    global HEALTH_CHECK_DICT, HEALTH_CHECK_VARS
    HEALTH_CHECK_DICT = dict()
    HEALTH_CHECK_VARS = {
        "connectivity": False,  # checks if the child is successfully spawned
        "gps": False  # Checks the GPS connectivity
    }
    return


def logger_config(file_name, log=True):
    global _file_handler_libRSE
    global _logger_libRSE
    global _counter
    global TESTCASE_ID
    health_check_var_init()
    TESTCASE_ID = file_name
    try:
        _logger_libRSE.removeHandler(_file_handler_libRSE)
    except Exception:
        pass
    _counter = 0
    SAFE_FW_PATH = os.path.abspath(config.SAFE_FW_PATH)
    file_name = re.sub(r"\.txt", ".log", file_name)
    log_file_name = "{}/logs/{}".format(SAFE_FW_PATH, file_name)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(filename=log_file_name, mode="w")
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    _file_handler_libRSE = file_handler
    _logger_libRSE = logger
    return 1


def logger_config_default():
    global _logger_libRSE
    _logger_libRSE = logging
    return 1


def logger_handler():
    global _file_handler_libRSE
    global _logger_libRSE
    file_handler = _file_handler_libRSE
    logger = _logger_libRSE
    logger.removeHandler(file_handler)
    return 1


def logger_wrapper(func):
    def wrapper(child, cmd, *args, **kwargs):
        global _logger_libRSE
        global _counter
        if not _logger_libRSE:
            logger_config_default()
        logger = _logger_libRSE
        command = cmd
        try:
            arg_str = " ".join([str(i) for i in args if type(i) is not list])
            # arg_str = arg_str.join([str(i) for i in kwargs if type(i) is not list])
        except Exception:
            arg_str = None
            print("Exception in logger_wrapper")
        cmd_with_args = "{} [{}]".format(command, arg_str)
        logger.info("STEP {}: {}".format(_counter, cmd_with_args))
        _counter += 1
        op = func(child, cmd, *args, **kwargs)
        op = re.sub(r"\n$", "", op) if type(op) is str else op
        try:
            status = "FAILURE" if int(op) < 0 else "SUCCESS"
        except Exception:
            # This exception occurs because of int(op)
            print("Exception in logger_wrapper")
            status = "SUCCESS"
        logger.info("OUTPUT: {}".format(op))
        logger.info("STATUS: {}\n".format(status))
        return op
    return wrapper


def logger_check_status(func):
    def wrapper(*args, **kwargs):
        global _logger_libRSE
        global _counter
        if not _logger_libRSE:
            logger_config_default()
        logger = _logger_libRSE
        command = "check status"
        try:
            arg_str = " ".join([str(i) for i in args if type(i) is not list])
            # arg_str = arg_str.join([str(i) for i in kwargs if type(i) is not list])
        except Exception:
            arg_str = None
            print("Exception in logger_wrapper")
        cmd_with_args = "{} [{}]".format(command, arg_str)
        logger.info("STEP {}: {}".format(_counter, cmd_with_args))
        _counter += 1
        op = func(*args, **kwargs)
        op = re.sub(r"\n$", "", op) if type(op) is str else op
        try:
            status = "FAILURE" if int(op) == 0 else "SUCCESS"
        except Exception:
            print("Exception in logger_wrapper")
            status = "SUCCESS"
        logger.info("OUTPUT: {}".format(op))
        logger.info("STATUS: {}\n".format(status))
        return op
    return wrapper


def print_to_log(op):
    global _logger_libRSE
    logger = _logger_libRSE
    if not logger:
        logger = logging
    logger.info(op)


def convert_time_mins(child, cmd, time_string):
    if re.search("-", time_string):
        time_string = time_string.split("-")[1].split(":")
    else:
        time_string = time_string.split(":")
    return sum(x * int(t) for x, t in zip([60, 1, 0], time_string))


def convert_time_secs(child, cmd, time_string):
    if re.search("-", time_string):
        time_string = time_string.split("-")[1].split(":")
    elif re.search(r"[\w]{3}\s+[\w]{3}\s+[\d]+\s+([\d]{2}\:[\d]{2}\:[\d]{2})\s+UTC\s+[\d]{4}", time_string):
        time_string = re.search(r"([\d]{2}\:[\d]{2}\:[\d]{2})\s+UTC", time_string)
        try:
            time_string = time_string.group(1)
            time_string = time_string.split(":")
        except AttributeError:
            print("AttributeError")
            return -1
    else:
        time_string = time_string.split(":")
    return sum(x * float(t) for x, t in zip([3600, 60, 1], time_string))


def convert_secs_into_time(child, cmd, total_secs):
    return str(datetime.timedelta(seconds=total_secs))


def obu_time_change(child, cmd, time_to_change):
    try:
        child.sendline("")
        child.expect("({})|({})".format(config._OBUPMT, config._EUOBUPMT))
        child.sendline('date +%T -s "{}"\r'.format(time_to_change))
        child.expect("({})|({})".format(config._OBUPMT, config._EUOBUPMT))
    except Exception:
        print("Exception Occured")
        return 0
    return 1


# Connect to RSU


def connect_to_device(dev_key, ip_addr=None):
    '''
    /********************************************************
    Description : This function is used to connect to the RSU device.
    Input Parameters :
    dev_key : Device key for example 'RSU0' which is declared as a key to a RSU dictionary, conatins user name, root user name, host ip, port, password, previlidged   password and root password required for the configuration of the board.
    ip_addr  : Ip address of the board for example '10.0.0.66',
    Return Value : connection status of the board ex:Connected to the board or not connected to the board.
    Type : External API
    Example : connect_to_device('RSU0', 'optional'): where 'RSU0' is the device key and '10.0.0.66' is the IP adress of
            the board, which is passed as a string value to the function. Here, the IP addr is optional
    *******************************************************************/
    '''
    global dev_conct_dict
    global _logger_libRSE
    global HEALTH_CHECK_DICT, HEALTH_CHECK_VARS
    logger = _logger_libRSE
    try:
        device_id = re.search("([\w\d]+)", dev_key).group(1)
    except AttributeError:
        print("No device Id found:")
        print("Assigining device ID to OBU0")
        device_id = "OBU0"
    HEALTH_CHECK_DICT[device_id] = HEALTH_CHECK_VARS
    health_check_vars = HEALTH_CHECK_DICT[device_id]
    if not logger:
        logger = logger_config_default()
    env_setup()
    child = None
    try:
        dev_key = str(dev_key)
        dev_lgn_dtils = config.RSU_Dict[dev_key]
    except KeyError:
        print("Please provide valid RSU key to login...")
        return None
    if ip_addr:
        dev_lgn_dtils["HOSTIP"] = ip_addr
    try:
        ssh_login = "ssh -q -o UserKnownHostsFile=/dev/null -o \
        StrictHostKeyChecking=no -p {0} {1}@{2}".format(dev_lgn_dtils["PORT"],
                                                        dev_lgn_dtils["UNAME"],
                                                        dev_lgn_dtils["HOSTIP"]
                                                        )
        print("ssh LOGIN:{}".format(ssh_login))
        for try_to_cnct in [1, 2, 3, 4]:
            try:
                print("Connecting to device:{} ".format(dev_key))
                child = pexpect.spawn(ssh_login)
                child.expect("[pP]assword:")
                sleep(1)
                child.sendline("{}\r".format(dev_lgn_dtils["PASSWORD"]))
                try:
                    child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT), timeout=5)
                    print_to_log("Connected to {} IP {}\n".format(
                        dev_key, dev_lgn_dtils["HOSTIP"]))
                except pexpect.TIMEOUT:
                    print("DEBUG:TIMEOUT occurred")
                break
            except pexpect.TIMEOUT:
                print("Failed to connect in {} time".format(try_to_cnct))
                if try_to_cnct == 4:
                    child.close(force=True)
                    print(
                        "Time out while connecting to dev:{}".format(dev_key))
                    health_check_vars["connectivity"] = False
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
                continue
            except pexpect.EOF:
                print("Number of logins are three or check the connection")
                if try_to_cnct == 4:
                    health_check_vars["connectivity"] = False
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        health_check_vars["connectivity"] = False
        return None
    sleep(2)
    wsmpHead.wsmp_head_init()
    TC_DEVICE_BUILD_NUM["rsu"] = show_version(child, "show version")
    dev_conct_dict[dev_key] = child
    return child


def ps_chk(child, dev_key):
    """
    This func is called in obu_connect_to_device API.
    This checks the presence of BSMd, Aerolink, GNSSd, and savari16093d processes.
    """
    child.sendline("ps")
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    # print(data)
    ps_list = ["AeroLinkv2xd", "BSMd", "savari16093d"]
    for dev_proc in ps_list:
        if not re.search(r"[\w\s\./]+{}".format(dev_proc), data, re.I):
            print("{} is not up.".format(dev_proc))
            print("Rebooting the device:{}".format(dev_key))
            child.sendline("reboot")
            print(child.readlines())
            sleep(90)
            return -1
        print("{} is up".format(dev_proc))
    return 1

# Connect to OBU


def obu_connect_to_device(dev_key, reset=None, ip_addr=None):
    '''
    /*************************************************************************
    Function Name : obu_connect_to_device
    Description : This function is used to connect to the OBU device.
    Input Parameters :
    dev_key : Device key for example 'OBU1' which is declared as a key to the dictionary contains user name, host ip,  password.
    ip_addr  : Ip address of the board for example '10.0.0.66'
    Return Value : connection status of the board ex:Connected to the board or not connected to the board etc.
    Type : External API
    Example : connect_to_device('OBU1')
            where 'OBU1' is the device key and ' ' is the IP adress of
            the board, which is passed as a string value to the function.
   ************************************************************************/
    '''
    global dev_conct_dict
    global _logger_libRSE
    logger = _logger_libRSE
    try:
        device_id = re.search("([\w\d]+)", dev_key).group(1)
    except AttributeError:
        print("No device Id found:")
        print("Assigining device ID to OBU0")
        device_id = "OBU0"
    print(device_id)
    HEALTH_CHECK_DICT[device_id] = HEALTH_CHECK_VARS
    health_check_vars = HEALTH_CHECK_DICT[device_id]
    if not logger:
        logger = logger_config_default()
    env_setup()
    dev_key = str(dev_key)
    try:
        dev_lgn_dtils = config.OBU_Dict[dev_key]
    except KeyError:
        print("Please provide valid OBU key to login")
        print("Invalid key for the device:{}".format(dev_key))
    if ip_addr:
        dev_lgn_dtils["OBU_HOSTIP"] = ip_addr
    try:
        ssh_login = "ssh -t -q -o UserKnownHostsFile=/dev/null \
                       -o StrictHostKeyChecking=no  {0}@{1} \
                       ".format(dev_lgn_dtils["OBU_UNAME"],
                                dev_lgn_dtils["OBU_HOSTIP"])
        print("ssh LOGIN:{}".format(ssh_login))
        for try_to_cnct in [1, 2, 3, 4]:
            try:
                print("Connecting to device:{} ".format(dev_key))
                child = pexpect.spawn(ssh_login)
                child.expect("[pP]assword:")
                sleep(1)
                child.sendline("{}\r".format(dev_lgn_dtils["OBU_PASSWORD"]))
                child.expect("({})|({})".format(
                    config._OBUPMT, config._EUOBUPMT))
                data = str(child.after, "utf-8")
                if re.search(r"EU16SIQC", data) and not re.search(r"eu",
                                                                  dev_key, re.I):
                    config.OBUPMT = "US16SIQC:?.+#"
                    child.sendline("select_stack US")
                    child.expect(config.OBUPMT, timeout=100)
                    child.sendcontrol("C")
                elif re.search(r"US16SIQC", data) and re.search(r"eu",
                                                                dev_key, re.I):
                    config.OBUPMT = "EU16SIQC:.+#"
                    child.sendline("select_stack EU")
                    child.expect(config.OBUPMT, timeout=100)
                    sleep(5)
                    child.sendcontrol("C")
                elif re.search(r"EU16SIQC", data) and re.search(r"eu",
                                                                dev_key, re.I):
                    config.OBUPMT = "EU16SIQC:.+#"
                else:
                    config.OBUPMT = "US16SIQC:?.+#"
                if re.search(r"^OBU", dev_key):
                    status = ps_chk(child, dev_key)
                    if status >= 0:
                        break
                    else:
                        continue
            except pexpect.TIMEOUT:
                print("Failed to connect in {} time".format(try_to_cnct))
                child.close(force=True)
                if try_to_cnct == 4:
                    child.close(force=True)
                    print(
                        "Time out while connecting to dev:{}".format(dev_key))
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
                continue
            except pexpect.EOF:
                print("Failed to connect in {} time".format(try_to_cnct))
                print("Number of logins are three or check the connection")
                if try_to_cnct == 4:
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None

    if re.search(r"eu", dev_key, re.I):
        if not reset:
            euobu_backup_defaultConf(child, default='No')
    wsmpHead.wsmp_head_init()
    logger.info("Connected to {} IP {}\n".format(
        dev_key, dev_lgn_dtils["OBU_HOSTIP"]))
    health_check_vars["connectivity"] = True
    if re.search("^obu", dev_key, re.I):
        TC_DEVICE_BUILD_NUM["obu"] = obu_cat(child, "cat /etc/banner")
    elif re.search("^euobu", dev_key, re.I):
        TC_DEVICE_BUILD_NUM["euobu"] = obu_cat(child, "cat /etc/banner")
    dev_conct_dict[dev_key] = child
    return child


def run_command_show(child, command):
    '''
    /*********************************************************************
    Function Name : run_command_show
    Description : This function is being used by all the commands starts with 'show'.
    Input Parameters :
       child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
       command  : show app status
    Return Value : It is the output after executing the command.
    Type : Internal API
    *****************************************************************/
    '''
    try:
        sleep(0.5)
        print("run_command_show:", command)
        try:
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT), timeout=5)
        except pexpect.TIMEOUT:
            # TODO: Need to fix this
            pass
            #print("Testing:Automation exception print")
        child.sendline("{0}\r".format(command))
        child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT),timeout=1000)
        data_return = child.before
        data_return = re.sub(r"\r", "", data_return.decode('utf-8'))
        data_return = re.sub(r"(\n)+", "\n", data_return)
        return data_return
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout while running the command:{}".format(command))
        return None


def run_command_config(child, command, *args, **kwargs):
    '''
    /*********************************************************************
    Function Name : run_command_config
    Description : This function is used for the configaration of the board.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : config app store-repeat ?
    *args : It can take many number of arguments.
    Return Value : Output of the command. If configuration fails, it will return the failure reason(connection status to the device).
                   Data type: String
    Type : Internal API
    Example : config app store-repeat ?
          configaration of store-repeat application . where ? is used to select match application name. For example ? matches color or colour both.
    *****************************************************************/
   '''
    try:
        if "?" in command:
            try:
                child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT), timeout=5)
            except pexpect.TIMEOUT:
                # TODO: Need to fix this
                print("Testing:Automation exception print")
            child.sendline("{}\r".format(command))
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
            data = child.before
            try:
                child.expect(r"\(?[Cc]onfig\)?#", timeout=10)
                child.sendline("exit\r")
            except pexpect.TIMEOUT:
                pass
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
            data = str(data, "utf-8")
            return data
        else:
            if len(args) > 0:
                command = "{} {}".format(command, args[0])
            try:
                child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT), timeout=5)
            except pexpect.TIMEOUT:
                # TODO: Need to fix this
                print("Testing:Automation exception print")
            child.sendline("{}\r".format(command))
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
            data_return = child.before
            data_return = str(data_return, "utf-8")
            data_return = re.sub(r"[\n\r]+", "", data_return)
            if not data_return:
                child.sendline("{}\r".format(command))
                child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
                data_return = child.before
                data_return = str(data_return, "utf-8")
                data_return = re.sub(r"[\n\r]+", "", data_return)
            index = re.search(r"{}".format(command), data_return, re.I)
            sub_str_data = data_return[index.end():]
            sub_str_data = sub_str_data.strip()
            print(sub_str_data)
            if not sub_str_data:
                return 1
            else:
                return sub_str_data
    except (TypeError, AttributeError):
        print("Not connected to the device or connection lost")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        print("Timeout Happened in run_command_config")
        return None


def show_app_store_repeat(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_store_repeat
    Description : This function is being used by all the commands starts with 'show app store-repeat'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app store-repeat
    args : status/streaming/security/all
    Return Value : It is the output after executing the command.
                   Data type: String
    Type : External API
    Example : show app store-repeat
          This command helps to view the apps available in the RSU such as tcd, ipv6, storeand repeat etc.
          RSU have limitations to acess the board, only 3 people can access the board.
    Output:
          StreetWAVE>> show app store-repeat status
          status = store-repeat is Disabled
    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    data_elements[1] = data_elements[1].strip()
    print(data_elements[1])
    if re.search(r"(enable)", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"(disable)", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_immediate_fwd(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_immediate_fwd
    Description : This function is being used by all the commands starts with 'show app immediate-forward'.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app immediate-forward streaming ip
    args : status/listenerport/streaming/tcdlisten/security/all/exit
    Return Value :It is the output after executing the command ex. Host name.
                   Data type: String
    Type : External API
    Example : show app immediate-forward streaming ip
          Streaming mode configuration allows RSU to replicate Immediate-Message in downstream RSUs.
          show immediate-forward  command gives output which contains the status of the app, RTCM, SPAT and MAP information.
    Output: StreetWAVE>> show app immediate-forward status

          status = immediate_forward app is disabled


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_immediate_fwd_tcdlisten(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_immediate_fwd_tcdlisten

    Description : This function is being used by all the commands starts with 'show_app_immediate_fwd_tcdlisten'.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app immediate-forward tcdlisten status

    Return Value :It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show app immediate-forward tcdlisten status
          This function is used to check the status of the TCD whether it is listening to incoming messages or not.
    Output :
            StreetWAVE>> show app immediate-forward tcdlisten

            tcdlisten = TCD Socket is not listening to the incoming msgs

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    data_list = data.split("\n")
    print(data_list[1])
    return data_list[1]
    # if re.search(r"not listening", data_list[1], re.I):
    #    return 0  # TCD socket is not listening to incoming msgs
    # else:
    #    return 1  # TCD socket is listening to incoming msgs


def show_app_gpsoutput(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_gpsoutput

    Description : This function is being used by all the commands starts with 'show_app_gpsoutput'.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show app gpsoutput status

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show app gpsoutput status
              This function is used to check the status of the gpsoutput.
    Output :
             StreetWAVE>> show app gpsoutput status

             status = gpsoutput app is disabled

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()

# Obsolete API dont use this.


def show_app_gpsoutput_string(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_gpsoutput_string

    Description : This function is being used by all the commands starts with 'show_app_gpsoutput_string'.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app gpsoutput status

    Return Value : It is the output after executing the command.
                   Data type: String

    Type : External API

    Example : show app gpsoutput status
              This function is used to check the status of the gpsoutput.
    output:
           StreetWAVE>> show app gpsoutput status

           status = gpsoutput app is disabled

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    print(data_list[2])
    # if re.search(r"not enable", command, re.I):
    #    return 0  # if not enable
    # else:
    #    return 1  # if enable


def show_app_radio(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_radio

    Description : This function is being used by all the commands starts with 'show_app_radio'.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app radio all
    args : radio1/radio2/all

    Return Value : It is the output after executing the command.
                   Data type: String

    Type : External API

    Example : show app radio radio1 cch
              show app radio radio2 svc
              show app radio radio1 svc
              This function is used to check the radio channel status.
    RSU contains two channels radio1 and radio2 where cch for control channel and  svc for service   channel
    Output :
              StreetWAVE>> show app radio all

    radio1 chan_mode          = 2
    radio2 chan_mode          = 2
    radio1-cont               = 178
    radio2 cont               = 172
    radio1-svc                = 174
    radio2-svc                = 184

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_ipv6_provider(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_ipv6_provider

    Description : This function is being used by all the commands starts with 'show_app_ipv6_provider'.
                   (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app ipv6 provider status

    Return Value : It is the output after executing the command.
                   Data type: String

    Type : External API

    Example : show app ipv6 provider status
              This function is used to check the status of the ipv6 provider application.
    OUTPUT:
         Status:
                Running
         Stats:
                IPV6-PROVIDER:
                          IpService Enabled : 0
                          Signing Enabled : 0
                          Current Service Channel : 0
                          Wsa Tx Packet: 26512
    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_dsrc_msgfwd(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_dsrc_msgfwd

    Description : This function is being used to check the configuaration of the RSU and Server to back up the infomation to the server at particular time.
                  (refer api_wrapper.txt for associated commands with the API)

    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show app dsrc msgfwd status

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show app dsrc msgfwd status
              Rsu when configured can capture selected DSRC messages and send the information
              to a backhouse server for further processing. The RSU can also be configured to start streaming
              the data to backhouse at specific time of the day.
    Output  :
              StreetWAVE>> show app dsrc-message-forward status

              status = dsrc_message_forward app is Disabled

    **************************************************************************/
    '''
    if len(args):
        command = command+" "+args[0]
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    if re.search(r"^show.*psid$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    print ("here")
    print (data_elements)
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_tcd(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_tcd

    Description : This function is being used to check the status of the tcd(traffic controller device) in the Rsu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show app tcd status

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show app tcd status
            This function is being used to check the status of the tcd (traffic controller device) in the RSU.
    Output :
             StreetWAVE>> show app tcd status

             status = disable


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_ntpclient(child, command, *args):
    '''

    /*********************************************************************
    Function Name: show_app_ntpclient

    Description : This function is being used to check information of the ntp client(NTP = Network Time Protocol)
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app ntpclient hostname

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String
    Type : External API

    Example : show app ntpclient hostname
            This function is being used to return the hostname of ntpclient
    Output :
            StreetWAVE>> show app ntpclient hostname

            hostname = 2401:4800:0:21::2


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    print(data_list[1])
    hostname = re.split(r"=", data_list[1])
    return hostname[1].strip()


def show_app_rtcm(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_rtcm

    Description : This function is being used to return output of all options under "show app rtcm" command.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app rtcm status

    Return Value : It is the output after executing the command.
                  returning 1 if it is eanble and returning 0 if it is disable.

    Type : External API

    Example : show app rtcm status
            This function is being used to check the status of the RTCM application.
    Output :
              StreetWAVE>> show app rtcm status

              status = rtcm app is enabled


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning None...")
        return None
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    data_elements = re.split(r"=", data_list[1])
    if re.search(r"enable", data_elements[1], re.I):
        return 1  # if enable
    elif(re.search(r"disable", data_elements[1], re.I)):
        return 0  # if disable
    elif data_elements[1].strip().isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1].strip()


def show_app_store_repeat_fp(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_app_store_repeat_fp
    ***we don't see any filepath option under the command "show app store-repeat".
    Description : This function is being used to give the information of the RTCM application.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show app store repeat fp ?

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show app store repeat fp ?

            This function is being used to show the store repeat application
            Output:

                  Status:
                        Running
                  Stats:
                       STORE-REPEAT:
                            Tx Packet : 197
                            Udp Tx Packet : 0
                            Signing Failures : 0
                            Num Active List Files : 1
                            Transmit Channel : 178

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    return data


def show_system_hwclock(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_hwclock

    Description : This function is being used to show the time and date of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system hwclock

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system hwclock
              This function is being used to show the time and date of the system.
           Output: Tue May 15 09:46:25 2018 -0.018988 seconds


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    return data_list[1]


def show_system_settings(child, command):
    '''
    /*********************************************************************
    Function Name: show_system_settings

    Description : This function is being used by all the commands starts with 'show system settings'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system settings hostname

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system settings hostname/timezone/all
              This function returns hostname and timezone depends on the command provided


    **************************************************************************/
    '''
    """ This function returns hostname and timezone depends on the command \
    provided"""
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    settings = re.split(r"=", data_list[1])
    return settings[1].strip()


def show_system_date(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_date

    Description : This function is being used to show the date of the system.
                 (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system date

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system date
              This function returns the date in hours,minute and seconds format ofsystem.
           Output:Tue May 15 09:50:53 UTC 2018


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if len(args) != 0:
        data_list = data.split("\n")
        print("UTC datetime:", data_list[1])
        timenow = datetime.datetime.strptime(
            data_list[1], "%a %b %d %H:%M:%S %Z %Y")
        timenow_plus_arg = timenow + datetime.timedelta(minutes=args[0])
        final_time = "{0}".format(
            timenow_plus_arg.strftime("%d/%m/%Y, %X"))
        return final_time[:-3]  # not needed seconds
    data_list = data.split("\n")
    return data_list[1]


def show_system_disk_usage(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_disk_usage

    Description : This function is being used by all the commands starts with 'show_system_disk_usage'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system disk usage

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system disk usage
              This function is used to view the disk usage.
          Output: Filesystem                Size      Used Available Use% Mounted on
                  rootfs                  189.5M    103.8M     81.8M  56% /
                  /dev/root               189.5M    103.8M     81.8M  56% /
                  tmpfs                   881.3M     88.0K    881.2M   0% /tmp
                  /dev/mmcblk0p3            3.3G      6.9M      3.1G   0% /nojournal
                  tmpfs                   512.0K         0    512.0K   0% /dev



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    # Removing the extra spaces.
    data_clean = [re.sub(r"(\s)+", " ", line) for line in data_list]
    # Splitting each line with space and returning the 5th \
    # element from the split list.
    data_elements = [line.split(" ") for line in data_clean[2: -1]]
    usage_per = [lst[4] for lst in data_elements]
    # We are extracting the numeric value and converting from str to int.
    use_val = [int(re.search(r"(\d+)", val).group(1)) for val in usage_per]
    return use_val


def show_system_memory_usage(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_memory_usage

    Description : This function is being used by all the commands starts with 'show_system_memory_usage'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system memory-usage

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system memory-usage
              This function is used to view the disk usage.
          Output:             total         used         free       shared      buffers
                  Mem:       1804848        51228      1753620          108          548
         -/+ buffers:              50680      1754168
                 Swap:            0            0            0



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    data_fields = re.sub(r"(\s)+", " ", data_list[1]).split(" ")
    data_clean = re.sub(r"(\s)+", " ", data_list[2])
    data_elements = data_clean.split(" ")
    if len(args) > 0:
        try:
            field = int(args[0])
        except ValueError:
            field = args[0]
        mem_usage_dict = {
            "{}".format(data_fields[0]): data_elements[0],
            "{}".format(data_fields[1]): data_elements[2],
            "{}".format(data_fields[3]): data_elements[3],
            "{}".format(data_fields[4]): data_elements[4],
            "{}".format(data_fields[5]): data_elements[5]
        }
        if type(args[0]) is str:
            return mem_usage_dict[field]
        elif type(field) is int:
            mem_usage = [int(num) for num in data_elements[2:]]
            return int(mem_usage[field])
        # Returning used, free, shared, and buffers.
    return mem_usage


def show_system_cpu_usage(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_cpu_usage

    Description : This function is being used by all the commands starts with 'show_system_cpu_usage'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system cpu-usage

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system cpu-usage
              This function is used to view the cpu usage.
          Output: 09:55:12     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest   %idle
                  09:55:13       0    0.00    0.00    2.08    0.00    0.00    2.08    0.00    0.00   95.83



    **************************************************************************/
    '''
    nsec = args[0] if len(args) else 10
    command = command + " " + str(nsec)
    print(command)
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    # Removing the extra spaces.
    data_clean = [re.sub(r"(\s)+", " ", line) for line in data_list]
    # Splitting each line with space and returning the 11th \
    # element from the split list.
    data_elements = [line.split(" ") for line in data_clean[2: -1]]
    idle = [lst[10] for lst in data_elements]
    # Converting from str to float.
    idle_val = [float(val) for val in idle]
    print(idle_val)
    # returns the avg of the nsec
    return sum(idle_val) / len(idle_val)


def show_system_sys_log(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_sys_log

    Description : This function is being used by all the commands starts with 'show_system_sys_log'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system sys log status

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system sys log status/loglevel/closeday/deleteday/deleteage/closetime/all
              This function is used to show the logs

       Output: enable = 1




    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    data_elements = re.split(r"=", data_list[1])
    if data_elements[1].isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1]


def show_system_uptime(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_uptime

    Description : This function is being used by all the commands starts with 'show_system_uptime'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system uptime

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system uptime
              This function is used to show uptime system.
      Output: 10:06:29 up  3:54,  load average: 0.52, 0.41, 0.40



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    print(data)
    if len(args) > 0:
        uptime = re.search(r"{}([\s\d:]+)".format(args[0]), data)
        print(uptime)
        if len(args) > 1:
            convert_type = args[1]
        else:
            convert_type = None
        try:
            uptime = uptime.group(1).strip()
            complete_time = uptime
            uptime = uptime.split(":")
        except AttributeError:
            return -1
        try:
            if convert_type == 'sec':
                total_uptime = convert_time_secs(
                    child, "convert time to secs", complete_time)
            elif convert_type == 'min':
                total_uptime = convert_time_mins(
                    child, "convert time to mins", complete_time)
            else:
                return complete_time
            #min = int(uptime[1])
            #hr_to_min = int(uptime[0]) * 60
            #total_uptime = min + hr_to_min
        except IndexError:
            min = int(uptime[0])
            total_uptime = min
        return total_uptime
    data_list = data.split("\n")
    return data_list[1]


def show_system_interface_log(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_interface_log

    Description : This function is being used by all the commands starts with 'show_system_interface_log'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system interface log ethernet

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system interface log ethernet/radio1/radio2/all
              This function is used to show interface log system(OBU/RSU).
       Output: StreetWAVE>> show system interface-log ethernet

               filesize        = 20
               timeout         = 1440
               generate        = 0



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    if re.search(r"interface_log", data_list[1]):
        if re.search(r"enable", data_list[1], re.I):
            return 1  # if enable
        else:
            return 0  # if disable
    else:
        # file size, timeout, generate
        data_elements = [int(re.split(r"=", line)[1])
                         for line in data_list[1: -1]]
        return data_elements


def show_system_network(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_network

    Description : This function is being used by all the commands starts with 'show_system_network'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system network eth0

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system network eth0/radio1/radio2/radio-all/all
              This function is used to show sytem network.
      Output:  show system network radio1
             proto          = static
             macaddr        = 09:AB:7A:C9:00:22
             ip6addr        =
             ip6gw          =

    **************************************************************************/
    '''
    try:
        data = run_command_show(child, command)
        print(data)
        if data is None:
            print("Received None and returning -1")
            return "-1"
        if re.search(r"^show.*all$", command):
            return data
        data_list = data.split("\n")
        data_elements = re.split(r"=", data_list[1])
        if data_elements[1].isnumeric():
            return int(data_elements[1])
        else:
            return data_elements[1].strip()
    except IndexError:
        print("No data available to return. Returning 0")
        return "0"

# ***************Not implemented**************


def show_system_firewall(child, comamnd, *args):
    print("This API is not implemented at")
    return "-1"
# ********************************************


def show_system_acl(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_acl

    Description : This function is being used by all the commands starts with 'show_system_acl'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system acl list ipv4

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API********************************************

    Example : show system acl list ipv4
            IPv4  = 202.123.3.4
            IPv4  = 192.168.21.109
            IPv4  = 192.168.21.185




    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    # Returning IP address from the given data.
    data_elements = [re.split(r"=", line)[1] for line in data_list[1:-1]]
    data_elements = [element.strip() for element in data_elements]
    return data_elements


def utils_list(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_utils_list
    *** Utils list is not implemented****

    Description : This function is being used by all the commands starts with 'show_utils_list'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show utils list ?

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show utils list ?
              This function is used to show the list of files in the system.



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    return data


def show_system_gpsstatus(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_gpsstatus

    Description : This function is being used by all the commands starts with 'show_system_gpstatus'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system gpsstaus

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system gpsstaus
              This function is used to view the gps status of the system.
       Output: StreetWAVE>> show system gpsstatus
              3D fix (Lat: 12.945227, Lon: 77.586324, Elev: 823.30)



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    if re.search(r"3D", data_list[1], re.I):
        return "3D FIX"
    elif re.search(r"2D", data_list[1], re.I):
        return "2D FIX"  # Returns if 2D or 3D fix available
    else:
        return "NO FIX"  # If no fix available


def show_system_process_list(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_process_list

    Description : This function is being used by all the commands starts with 'show_system_process_list'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system process list

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system process list
              This function is used to show the list of process in the system(OBU/RSU).
       Output: show system process-list
   PID USER       VSZ STAT COMMAND
    1 root      1368 S    /sbin/procd
    2 root         0 SW   [kthreadd]
    3 root         0 SW   [ksoftirqd/0]
    4 root         0 SW   [kworker/0:0]
    5 root         0 SW<  [kworker/0:0H]
    7 root         0 SW   [rcu_sched]
    8 root         0 SW   [rcu_bh]
    9 root         0 SW   [migration/0]
   10 root         0 SW   [migration/1]
   11 root         0 SW   [ksoftirqd/1]
   13 root         0 SW<  [kworker/1:0H]
   14 root         0 SW<  [khelper]

   **************************************************************************/
   '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    return data


def show_system_rsu_uptime(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_rsu_uptime

    Description : This function is being used by all the commands starts with 'show_system_rsu_uptime'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system rsu-uptime gpsd

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system rsu-uptime gpsd {"up"}
        Output:  show system rsu-uptime gpsd
        up 0 days 04:15:53
        restarted: 0 times


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    print(data)
    data_list = data.split("\n")
    data_time = [re.findall(r"(\d+)", line) for line in data_list[1:-1]]
    # Converting string to int
    uptime_list = [int(i) for string in data_time for i in string]
    uptime = uptime_list[1] * 60 + uptime_list[2] * 60 + uptime_list[3]
    if len(args) > 0:
        keyword_dict = {
            "up": uptime,
            "restart": uptime_list[4]
        }
        return keyword_dict[args[0].strip()]
    return [uptime, uptime_list[4]]


def show_system_rsu_stats(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_rsu_stats

    Description : This function is being used by all the commands starts with 'show_system_rsu_stats'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system rsu-stats store-repeat

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system rsu-stats store-repeat/immediate-forward/ipv6-provider/rtcm_msg_fwd/dsrc-message-forward/all
        Output: StreetWAVE>> show system rsu-stats store-repeat
  Status:
        Not Running
  Stats:
        STORE-REPEAT:
                Tx Packet                : 0
                Udp Tx Packet            : 0
                Transmit Channel         : 0
                Invalid Active StoreRepeatDB file. Please refer syslog for details


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    try:
        option = args[0]
        print (option)
    except IndexError:
        print("No option provided")
        print(data)
        return 1
    print(data)
    if re.search("dsrc",command):
        dict1 = {}
        try:
            psid = args[0]
            intf = args[1]
            option = args[2]
        except IndexError:
            print("psid/interface not provided")
            return -1
        data = re.split("[a-zA-Z\s]+ath[\d]:\n",data)[1:]
        ind=0
        for val in data:
            for val2 in val.split("\n")[1:]:
                if val2:
                    dict1[f"ath{ind}-{val2.split()[0].lower()}"] = val2.split()[1:]
            ind=ind+1
        try:
            (rx,tx,drop)=dict1[f'{intf}-{psid}']
            return eval(option)
        except KeyError:
            print("Provide valid interface/PSID")
            return -1
    else:
        data_split = re.split(r"\n", data)
        for line in data_split:
            if option in line:
                value = re.split(r":", line)[1]
                value = value.strip()
                return value
        values = re.findall(r"\b(\d+)\b", data)
        val = [int(i) for i in values]
        return val


def show_system_ndppd(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_ndppd

    Description : This function is being used by all the commands starts with 'show_system_ndppd'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system ndppd rule

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system ndppd rule
        Output: show system ndppd rule
         rule = fdca:39c0:a830:4444::/64



    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    print(data_list[1])
    ndppd = re.split(r"=", data_list[1])
    return ndppd[1].strip()


def show_system_app_status(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_status

    Description : This function is going show system status
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system app-status

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system app-status  {pattern}
        Output:
                 Enabled       Idle      Running          Not-Running
Service:
--------
SPAT           N             _         _                    _

MAP            N             _         _                    _

STORE-REPEAT   N             _         _                    _

WSA/IPV6       N             _         _                    _

DSRC-MSG-FORWD N             _         _                    _

RTCM           _             _         _                    Y

Oper Mode:
----------
IFM(MASTER)    N             _         _                    _

SRM(MASTER)    N             _         _                    _

IFM(SLAVE)     N             _         _                    _

SRM(SLAVE)     N             _         _                    _


--------------------------------------------------------------

Halt Last Executed On:	 Tue May 15 09:05:54 UTC 2018

Run Last Executed On:	 Tue May 15 09:06:22 UTC 2018
--------------------------------------------------------------
    **************************************************************************/
    '''
    try:
        child.expect(config.CLIPMT)
        child.sendline("show system date")
        child.expect(config.CLIPMT)
    except pexpect.TIMEOUT:
        print("#Testing:TImeout in show_system_app_status")
    child.sendline(command)
    child.expect(config.CLIPMT)
    data = str(child.before, "utf-8")
    data_return = re.sub(r"\r", "", data)
    data_return = re.sub(r"(\n)+", "\n", data_return)
    data_list = data.split("\n")
    if(len(args) != 0):
        pattern = args[0]
        print(pattern)
        value = [val for val in data_list if(
            re.search(pattern, val, re.I))]
        print(data)
        value_list = [re.sub(r"(\s+)", " ", val) for val in value]
        return value_list[0].split(" ")
    else:
        print(data)
        return 1


def show_system_ssh(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_ssh

    Description : This function is being used by all the commands starts with 'show_system_ssh'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system ssh port

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system ssh port/timeout/all
        Output: StreetWAVE>> show system ssh port
        port = 51012

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    print(data_list[1])
    ssh_value = re.split(r"=", data_list[1])
    return int(ssh_value[1].strip())


def show_system_snmp_notification(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_snmp_notification

    Description : This function is being used by all the commands starts with 'show_system_ssh'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show system snmp notifiaction ipaddr

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system snmp notifiaction ipaddr/port/all
        Output: StreetWAVE>> show system snmp-notification ipaddr
        ipaddr = FF02::25


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    if re.search(r"^show.*all$", command):
        return data
    data_list = data.split("\n")
    data_elements = re.split(r"=", data_list[1])
    if data_elements[1].isnumeric():
        return int(data_elements[1])
    else:
        return data_elements[1]

# This command has been removed


def show_rsu_set(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_system_rsu_set
    *** not implemeted****
    Description : This function is being used by all the commands starts with 'show_system_rsu_set'.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show system rsu-set

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show system rsu-set


    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    data_elements = re.split(r"=", data_list[1])
    print(data_list[1])
    return data_elements[1].strip()


def show_version(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_version

    Description : This function is being used to check the version of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : show version

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show version
       Output: StreetWAVE>> show version
               SW1000-5.12.99.51



    **************************************************************************/
    '''
    global _logger_libRSE
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    _logger_libRSE.info(data_list[1])
    return data_list[1].strip()


def show_serial(child, command, *args):
    '''
    /*********************************************************************
    Function Name: show_serial

    Description : This function is being used to check the version of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show serail-number

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show serail-number
       Output: StreetWAVE>> show serial-number
              XXX

    **************************************************************************/
    '''
    data = run_command_show(child, command)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    data_list = data.split("\n")
    print(data_list[1])
    return data_list[1].strip()


def show_support_log(child, command):
    '''
    /*********************************************************************
    Function Name: show_support_log

    Description : This function is being used to show the log of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  show support log

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : External API

    Example : show support log
       Output: StreetWAVE>> show support-log
       Log file successfully generated.


    **************************************************************************/
    '''
    try:
        child.expect(config.CLIPMT)
        child.sendline("{}\r".format(command))
        child.expect(config.CLIPMT, timeout=60)
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
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        return None


def shell_mode(child, cmd, *args):
    '''
   /*********************************************
   Function Name: shell_mode
    **** not implemented in the board****

    Description : This function is being used to enter the shell mode of the RSU.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  shell mode

    Return Value : It is the output after executing the command ex. Host name.
                   Data type: String

    Type : Function

    Example : shell mode
  ***************************************************/
    '''

    dev_lgn_dtils = config.RSU_Dict[args[0]]
    try:
        print(child.buffer)
        print("A1", child.after)
        child.expect("login")
        print(child.buffer)
        print("A2", child.after)
        child.sendline("{}".format(dev_lgn_dtils["ROOT_UNAME"]))
        child.expect("[pP]assword")
        print(child.buffer)
        print("A3", child.after)
        child.sendline("{}".format(dev_lgn_dtils["ROOT_PASSWORD"]))
        child.expect("{}|{}".format(config.SHELLPMT,config.MODIFIED_SHELLPMT))
        print("Entered into the shell mode...")
        child.sendline("")
        child.expect("{}|{}".format(config.SHELLPMT,config.MODIFIED_SHELLPMT))
        return 1
    except pexpect.TIMEOUT:
        print("Failed to enter shell mode")
        return None


def rsu_ifconfig(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: rsu_ifconfig
    Description : This function is being used to know the inforamation of thr system interface.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : rsu ifconfig

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : rsu ifconfig
    Output:
root@StreetWAVE:~# ifconfig
ath0      Link encap:Ethernet  HWaddr 00:13:01:30:AA:00
          inet6 addr: fe80::213:1ff:fe30:aa00/64 Scope:Link
          inet6 addr: 2001:db8:f101:8000::15/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1492  Metric:1
          RX packets:35127 errors:0 dropped:34911 overruns:0 frame:0
          TX packets:24752 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:3000
          RX bytes:9928464 (9.4 MiB)  TX bytes:4376221 (4.1 MiB)

ath1      Link encap:Ethernet  HWaddr 00:13:01:30:BB:00
          inet6 addr: fe80::213:1ff:fe30:bb00/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1492  Metric:1
          RX packets:72544 errors:0 dropped:72508 overruns:0 frame:0
          TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:3000
          RX bytes:8497195 (8.1 MiB)  TX bytes:818 (818.0 B)

eth0      Link encap:Ethernet  HWaddr EE:A4:C7:36:DE:BC
          inet addr:10.0.0.221  Bcast:10.0.0.255  Mask:255.255.255.0
          inet6 addr: 2001:db8:f101:9000::5/64 Scope:Global
          inet6 addr: fe80::eca4:c7ff:fe36:debc/64 Scope:Link
          UP BROADCAST RUNNING ALLMULTI MULTICAST  MTU:1500  Metric:1
          RX packets:4805 errors:0 dropped:0 overruns:0 frame:0
          TX packets:775 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:513663 (501.6 KiB)  TX bytes:180370 (176.1 KiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:98141 errors:0 dropped:0 overruns:0 frame:0
          TX packets:98141 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:8175902 (7.7 MiB)  TX bytes:8175902 (7.7 MiB)
   ******************************************************/
   '''
    command = cmd.split("rsu")[1].strip()
    try:
        option = args[0]
    except IndexError:
        option = 0
        print("Please provide option")
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline("{} > ifconfig.txt".format(command))
    child.expect(config.SHELLPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    # "file copy" it is a dummy variable
    file_copy(child, "file copy", "ifconfig.txt")
    with open("{}/ifconfig.txt".format(dest_path), "r") as ifconfig:
        data = ifconfig.read()
    data_dict = {
        "HWaddr": re.search("HWaddr\s?((([\da-fA-F]){2}:?){6})", data),
        "inet addr": re.search("inet addr:\s?((\d{1,3}\.?){4})", data),
        "inet6 addr":
        re.search("inet6 addr:\s?([\da-fA-F:]+/64)", data),
        "RX packets": re.search(r"RX packets:(\d+)", data),
        "TX packets": re.search(r"TX packets:(\d+)", data),
        "RX dropped": re.search(r"RX.*dropped:(\d+)", data),
        "RX errors": re.search(r"RX.*errors:(\d+)", data),
        "TX dropped": re.search(r"TX.*dropped:(\d+)", data),
        "TX errors": re.search(r"TX.*errors:(\d+)", data),
    }
    print("option:", option)
    if not option:
        print("No option provided, displaying ifconfig output")
        print(data)
        return 0
    try:
        re_object = data_dict[option]
        value = re_object.group(1)
    except (KeyError, AttributeError):
        print("Please provide valid option or Pattern not found")
        return "-1"
    return int(value) if value.isnumeric() else value


def file_config(child, cmd, *args):
    '''
   /*********************************************
    Function Name: file_config
    Description : This function is being used to config the file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  file config {/etc/config/TIMDB/timfile.db,TxChannel,174}

    Return Value : status of the configuration of the file.
                   Data type: String

    Type : External API

    Example : file config {/etc/config/TIMDB/timfile.db,TxChannel,174}
  ***************************************************/
  '''
    try:
        child.sendline("")
        child.expect(config.SHELLPMT)
        try:
            path = args[0]
            field_to_change = args[1]
            value = args[2]
            if len(args) > 3 and args[3] == 'space':
                delimiter = ' '
            else:
                delimiter = '='
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        if re.search(r"/", value):
            value = re.sub("/", r"\/", value)
            print(value)
        if value == "NULL":
            command = r"sed -i 's/^{0} *{1} *\"*[_\.\-\s:/0-9a-zA-Z]*\"*/{0}          = /g' \
                    {3}".format(field_to_change, delimiter, value, path)
        elif "\"" not in value:
            command = r"sed -i 's/^{0} *{1} *[_\.\-\s:/0-9a-zA-Z]*/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        else:
            command = r"sed -i 's/^{0} *{1} *\"[_\.\-\s:/0-9a-zA-Z]*\"/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        print(command)
        child.sendline(command)
        child.expect(config.SHELLPMT)
        err_stat = child.before
        err_stat = str(err_stat, "utf-8")
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_change, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.SHELLPMT)
        sleep(1)
        awk_data = str(child.before, "utf-8")
        print(awk_data)
        if re.search(r"No such file", err_stat, re.I):
            print("err_stat")
            return 0
        # print("file successfully configured")
        child.sendline("")
        child.expect(config.SHELLPMT)
        print(child.before)
        return 1
    except IndexError:
        print("Please provide the valid number of arguments")
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in file_config function")


def remove_files_from_path(child, cmd, path, filename_pattern=None):
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        if filename_pattern:
            command = f"rm {path}/{filename_pattern}*"
        else:
            command = f"rm -r {path}"
        print(command)
        child.sendline(command)
        child.expect(config.OBUPMT)
        data = child.before
        data = str(data, "utf-8")
        if re.search("No such file or directory", data, re.I):
            print("Given Path/file is invalid")
            return -1
        else:
            try:
                command = command.split("rm -r")[1]
            except IndexError:
                command = command.split("rm ")[1]
            child.sendline(f"ls -l {command}")
            child.expect(config.OBUPMT)
            data = child.before
            data = str(data, "utf-8")
            return data
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def file_copy(child, cmd, file_name):
    '''
   /*********************************************
    Function Name: file_copy
    Description : This function is being used to copy the file from the device to the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   file copy {/etc/config/TIMDB/timfile.db}

    Return Value : status of the configuration of the file.
                   Data type: String

    Type : External API

    Example : file copy {/etc/config/TIMDB/timfile.db}
   **************************************************/
   '''
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline("scp {0} {1}@{2}:{3}/resource/files/".format(
        file_name, config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH))
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.SHELLPMT)
        return 1
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.SHELLPMT)
        return 1


def rsu_scp_sys(child, cmd, *args):
    try:
        source = args[0]
        dest = args[1]
        if re.search(r"resource", source):
            source = source.split("resource")[1]
            command = "scp {0}@{1}:{2}/resource{3} {4}".format(config.SYS_UNAME,
                                                               config.SYS_HOST,
                                                               config.SAFE_FW_PATH,
                                                               source,
                                                               dest)
        else:
            command = "scp {}@{}:{} {}".format(config.SYS_UNAME, config.SYS_HOST,
                                               source, dest)
        print("RSU command:{}".format(command))
        child.sendline("")
        child.expect(config.SHELLPMT)
        child.sendline("{}".format(command))
        try:
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting", timeout=5)
            child.sendline("y\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        sleep(2)
        child.expect(config.SHELLPMT, timeout=1000)
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


def log_error_checker(child, command, *args):
    '''
   /*********************************************
    Function Name: log_error_checker
    Description : This function is being used to check the error in the system logs.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :
    args: error pattren.

    Return Value : Error  pattern in the logs
                   Data type: String

    Type : External API

    Example : log error checker ???? refer .txt file and give example.
   **************************************************/
   '''
    if len(args) > 1:
        path = args[0]
        pattern = args[1]
        pattern = re.escape(pattern)
        print("PATTERN:{}".format(pattern))
    else:
        print("Provide the pattern to search")
        return -1
    try:
        child.sendline("")
        child.expect(config.SHELLPMT)
        abs_path = os.path.abspath(path)
        child.sendline("cd {}".format(abs_path))
        sleep(2)
        child.expect(config.SHELLPMT)
        child.sendline("")
        child.expect(config.SHELLPMT)
        sys_cmd = "ls -rt | tail -n 1"
        child.sendline("{}".format(sys_cmd))
        child.sendline("")
        child.expect(config.SHELLPMT, timeout=300)
        data = child.before
        data = str(data, "utf-8")
        data = re.sub(r"(\r)|(ls -rt \| tail -n 1)", "", data)
        data = re.sub(r"(\n)|(root@)", "", data)
        file_name = data.strip()
        print(file_name)
        file_copy(child, "file copy", file_name)
        HOME = os.getenv("HOME")
        time_stamp = datetime.datetime.now().strftime("%b_%d_%I:%M:%S_%Y")
        file_name = "{0}/resource/files/{1}".format(config.SAFE_FW_PATH,
                                                    file_name)
        print(file_name)
        os.system(
            "cp {} {}/SAFElogs/{}_log.txt".format(file_name, HOME, time_stamp))
        print("File copied to resource/files")
        grep_result = None
        with open(file_name) as sys_log:
            sys_log_data = sys_log.readlines()
            pattern = re.compile(pattern)
            pattern_data = [line for line in sys_log_data
                            if pattern.search(line)]
            try:
                def func(x, y): return x + "\n" + y
                grep_result = reduce(func, pattern_data)
            except TypeError:
                print("No specified pattern found")
                print("Returning -1")
                return "-1"
        return grep_result

    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def tcp_dump_backup(file_path):
    timestamp = datetime.datetime.now()
    date = str(timestamp.date())
    time = str(timestamp.time())
    timestamp = "{}_{}".format(date, time)
    tcp_name = os.path.basename(file_path)
    copy = "cp {} {}/SAFElogs/{}_{}".format(file_path,
                                            _HOME, timestamp, tcp_name)
    print("\n")
    # print("COPYPATH:{}".format(copy))
    os.system(copy)


def tcp_dump(child, cmd, interface, macaddr, io, msg=None):
    '''
   /*********************************************
    Function Name: tcp_dump
    Description : This function is being used to capture all the packets.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : tcp-dump
    macaddr: adress of the system from which we want to capture the packets.
    interface: interface number
    io:
    Return Value : Macc address Or Hexdump
                   Data type: String

    Type : External API

    Example : tcp-dump
      Output: mac address or hex dump



   **************************************************/
   '''
    global _HEXDUMP, _HOME
    if not msg:
        msg = "hex"
    hexdump = None
    child.sendline("")
    child.expect(config.SHELLPMT)
    command = "tcpdump -i {} ether host {} -{} -X > tcpdump.txt".format(
        interface, macaddr, io)
    child.sendline(command)
    sleep(7)
    child.sendcontrol("C")
    child.expect(config.SHELLPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    dest_path = "{}/resource/files".format(dest_path)
    command = "scp {} {}@{}:{}".format("tcpdump.txt", config.SYS_UNAME,
                                       config.SYS_HOST, dest_path)
    scp_command_shell(child, command)
    sleep(2)
    file_path = "{}/tcpdump.txt".format(dest_path)
    tcp_dump_backup(file_path)
    with open(file_path) as tcpdump:
        hexfile = tcpdump.read()
    hexfile = re.sub(r"\t", "", hexfile)
    time_ind = [ind.start() for ind in
                re.finditer("\d\d:\d\d:\d\d\.\d", hexfile)]
    time_ind_pairs = zip(time_ind[:-1], time_ind[1:])

    def hexcode_gen():
        next(time_ind_pairs)
        for ind1, ind2 in time_ind_pairs:
            # Getting index for the start of hexcode
            index_t = re.search(r"0x0000:", hexfile[ind1:ind2]).start()
            if not index_t:
                return -1
            hexcode = hexfile[ind1+index_t:ind2]
            yield hexcode
    try:
        hex_gen = hexcode_gen()
        if hex_gen == -1:
            return "-1"
        print(type(msg))
        if re.search("tim", msg):
            for hc in hex_gen:
                if re.search(r"80\s?03", hc):
                    hexdump = hc
                    break
        elif re.search("(spat)|(map)", msg):
            for hc in hex_gen:
                if re.search(r"80\s?02", hc):
                    hexdump = hc
                    break
        else:
            for hc in hex_gen:
                if re.search(r"80\s?07", hc):
                    hexdump = hc
                    break
        if not hexdump:
            print(r"No hex data found")
            return "-1"
        _HEXDUMP = True
    except (IndexError, AttributeError):
        print("No hexdump found for the given macaddr")
        _HEXDUMP = False
        return "-1"
    print("\n")
    print("RAW_HEX_CODE:\n{}".format(hexdump))
    tcpdump = re.findall(r"\b[\da-fA-F]{4}\b", hexdump)
    #_temp_len = re.search("length (\d+):", hexdump).group(1)
    # if len(_temp_len) == 4:
    #    tcpdump = tcpdump[1:]

    def func(x, y): return x + y
    tcpdump = reduce(func, tcpdump)
    return tcpdump


def sudo_copy(child, cmd, file_name, dest):
    os.chdir(dest)
    src = f"{config.SAFE_FW_PATH}/resource/files/{file_name}"
    HOME = os.getenv("HOME")
    copy = "sudo cp {} {}".format(src, dest)
    print(copy)
    ps = pexpect.spawn(copy)
    ps.expect("[pP]assword")
    sleep(1)
    ps.sendline(config.SYS_PASSWORD)
    try:
        ps.expect("$")
    except:
        pass
    if file_name in os.listdir(dest):
        print("Copy successful")
        return 1
    else:
        print("Copy failed")
        return -1


def obu_file_copy(child, file_name):
    '''
   /*********************************************
    Function Name: obu_file_copy
    Description : This function is being used to copy the file from device to system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    file_name : File name which will be copied in to the obu.

    Return Value : where 1 represent the sucessfull copy.
                   data type: int

    Type : Function

    Example : obu file copy {'source','destination'}
   **************************************************/
    '''
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("scp {0} {1}@{2}:{3}/resource/files/".format(
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


def obu_date(child, cmd, Format=None):
    '''
            /*********************************************************************
            Function Name: obu_date
                    Description : This function is being used to run "date" command on OBU
                    Input Parameters :
                    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
                    command  : date
                    output format : {%d - for date
                              %m - for mins
                              %s - for secs
                              %H - for Hrs
                              %M - for Mins
                              %S - for Secs
                              %y - for two decimal year eg:- 18 for 2018
                              %Y - for four decimal year eg:- 2018}
                    Return Value : Result of the command if no Format is provided else returns Formated value.
                                   Data type: String
            **************************************************************************/
            '''
    cmd1 = cmd.split("obu")[1].strip()
    command = cmd1
    print("command:{}".format(command))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect('root@'+config.OBUPMT, timeout=20)
    data = child.before
    data = str(data, "utf-8")
    data = data.lstrip(' '+command)
    data = data.strip()
    if Format:
        d = datetime.datetime.strptime(data, "%a %b %d %H:%M:%S %Z %Y")
        try:
            cov_data = d.strftime(Format)
            return cov_data
        except Exception:
            print('Format is Invalid!')
            return -1
    print(data)
    return data


def obu_hwclock(child, cmd, Format=None):
    '''
            /*********************************************************************
            Function Name: obu_hwclock
                    Description : This function is being used to run "hwclock" command on OBU
                    Input Parameters :
                    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
                    command  : hwclock
                    output format : {%d - for date
                              %m - for mins
                              %s - for secs
                              %H - for Hrs
                              %M - for Mins
                              %S - for Secs
                              %y - for two decimal year eg:- 18 for 2018
                              %Y - for four decimal year eg:- 2018}
                    Return Value : Result of the command if no Format is provided else returns Formated value.
                                   Data type: String
            **************************************************************************/
            '''
    cmd1 = cmd.split("obu")[1].strip()
    command = cmd1
    print("command:{}".format(command))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect('root@'+config.OBUPMT, timeout=20)
    data = child.before
    data = str(data, "utf-8")
    data = data.lstrip(' '+command)
    data = data.strip()
    if Format:
        data = " ".join(data.split(" ")[:-3])
        d = datetime.datetime.strptime(data, "%a %b %d %H:%M:%S %Y")
        try:
            cov_data = d.strftime(Format)
            return cov_data
        except Exception:
            print('Format is Invalid!')
            return -1
    print(data)
    return data

def obu_hwclock_c(child, cmd, Format=None, sleep_val=20):
    cmd1 = cmd.split("obu")[1].strip()
    command = cmd1
    print("command:{}".format(command))
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    sleep (sleep_val)
    child.sendcontrol("C")
    child.expect(config.OBUPMT)
    data = child.before
    data = str(data, "utf-8")
    print (data)
    data_list=data.split("\n")
    hw_time = float(data_list[2].split("   ")[0])
    sys_time = float(data_list[2].split("   ")[1])
    dt1 = datetime.datetime.fromtimestamp(hw_time)
    dt2 = datetime.datetime.fromtimestamp(sys_time)
    rd = dateutil.relativedelta.relativedelta (dt2, dt1)
    #print(rd)
    print ("{} minutes {} seconds and {} milliseconds".format(rd.minutes, rd.seconds, (rd.microseconds * 0.001)))
    rd_milli_sec = round(abs(rd.minutes * 60000) + abs(rd.seconds * 1000) + (rd.microseconds * 0.001))
    return rd_milli_sec


def obu_log_error_checker(child, command, *args):
    '''
   /*********************************************
    Function Name: obu_log_error_checker
    Description : This function is being used to check the obu error in the system logs.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :
    args: pattren of the error.

    Return Value : error pattern in the logs.
                   Data type: String

    Type : Function

    Example : obu log error checker ???? .txt file refer
   **************************************************/
    '''
    if len(args) > 1:
        path = args[0]
        pattern = "{}".format(re.escape(args[1]))
        print("PATTERN:{}".format(pattern))
    else:
        print("Provide the pattern to search")
        return -1
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        abs_path = os.path.abspath(path)
        child.sendline("cd {}".format(abs_path))
        sleep(2)
        child.expect(config.OBUPMT)
        child.sendline("")
        child.expect(config.OBUPMT)
        sys_cmd = "ls -rt | tail -n 1"
        child.sendline("{}".format(sys_cmd))
        child.sendline("")
        child.expect(config.OBUPMT)
        data = child.before
        data = str(data, "utf-8")
        data = re.sub(r"(\r)|(ls -rt \| tail -n 1)", "", data)
        data = re.sub(r"(\n)|(root@)", "", data)
        file_name = data.strip()
        print(file_name)
        obu_file_copy(child, file_name)
        print("File copied to resource/file")
        grep_result = None
        with open("{0}/resource/files/{1}".format(config.SAFE_FW_PATH,
                                                  file_name)) as sys_log:
            sys_log_data = sys_log.readlines()
            pattern = re.compile(pattern)
            pattern_data = [line for line in sys_log_data
                            if pattern.search(line)]
            try:
                def func(x, y): return x + "\n" + y
                grep_result = reduce(func, pattern_data)
            except TypeError:
                print("No specified patter found")
                print("Returning -1")
                return "-1"
        os.remove("{0}/resource/files/{1}".format(config.SAFE_FW_PATH,
                                                  file_name))
        return grep_result
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def direct_to_shell_mode(child, command, *args):
    '''
   /*********************************************
    Function Name: direct_to_shell_mode
    Description : This function is being used to switch system dircetly from CLI mode to shell mode.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  direct_to_shell_mode (child,"pr enable",'10.0.0.187')

    Return Value : status regarding the sucess or failure in the mode switching.
                   Data type: String data.

    Type : External API

    Example : direct_to_shell_mode {child,"pr enable",'10.0.0.187'}
   *************************************************/
   '''
    device = args[0]
    try:
        status = pr_enable(child, "pr enable", device)
    except pexpect.TIMEOUT:
        status = 1
        pass
    if status:
        print("Entered into privileged mode")
    else:
        print("Failed to enter privileged mode")
        return 0
    sleep(2)
    status = shell_drop(child, "shell-drop")
    if status:
        print("Entered into shell drop mode")
    else:
        print("Failed to enter shell drop mode")
        return 0
    sleep(2)
    status = shell_mode(child, "shell mode", device)
    if status:
        print("Entered into shell mode")
    else:
        print("Failed to enter shell mode")
        return 0
    return 1


def scp_command_shell(child, command):
    '''
   /*************************************************
    Function Name: scp_command_shell
    Description : This function is being used to copy  files to the shell.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  scp command shell {source, destination}

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : scp command shell {source, destination}
   *************************************************/
   '''
    try:
        # print("\n")
        # print("SCP_COMMAND:{}".format(command))
        child.sendline("")
        child.expect(config.SHELLPMT)
        child.sendline(command)
        try:
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting")
            child.sendline("y\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def scp_command_cli(child, cmd, *args):
    '''
   /*************************************************
    Function Name: scp_command_cli
    Description : This function is being used to copy files to the cli.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  scp command cli {source, Destination}

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : scp command cli {source, Destination}
   *************************************************/
    '''
    command = None
    if re.search(r"utils copy /?resource", cmd):
        command = cmd.split("resource")[1]
        command = r"utils copy {0}:scp://{1}:{2}/resource{3}".format(
            config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH, command)
    elif re.search(r"utils copy support-log", cmd):
        split_cmd = cmd.split("resource")
        command = r"{0} {1}:scp://{2}:{3}/resource{4}".format(split_cmd[0],
                                                              config.SYS_UNAME,
                                                              config.SYS_HOST,
                                                              config.SAFE_FW_PATH,
                                                              split_cmd[1])
    else:
        command = cmd
    print("command:{}".format(command))
    try:
        child.expect(config.CLIPMT)
        child.sendline(command)
        try:
            child.expect("password:")
            child.sendline("{}\r".format(config.SYS_PASSWORD))
            child.expect(config.CLIPMT, timeout=1000)
        except pexpect.TIMEOUT:
            try:
                child.expect("connecting", timeout=5)
            except pexpect.TIMEOUT:
                child.expect(config.CLIPMT)
                ret_stat = child.before
                ret_stat = str(ret_stat, "utf-8")
                sleep(2)
                return ret_stat
            child.sendline("y\r")
            child.expect("password:")
            child.sendline("{}\r".format(config.SYS_PASSWORD))
            child.expect(config.CLIPMT, timeout=1000)
        ret_stat = child.before
        ret_stat = str(ret_stat, "utf-8")
        sleep(2)
        return ret_stat
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def utils_rsu_upgrade(child, command, *args):
    '''
   /*****************************************************
    Function Name: utils_rsu_upgrade
    Description : This function is being used to upgrade the image in the RSU.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  utils rsu-upgrade -n

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : utils rsu-upgrade -n
   ******************************************************/
    '''
    try:
        child.sendline("")
        child.expect(config.CLIPMT)
        if len(args) < 1:
            print("Please provide image name")
            return None
        cmd = command + " " + str(args[0])
        child.sendline("{}\r".format(cmd))
        sleep(60)
        print("System upgraded susccessfully")
        return 1
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.TIMEOUT:
        print("Time out happened in rsu-upgrade...")
        print("Returning None...")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None

# Following API is obsolete. Instead use utils_rsu_upgrade


def utils_sys_upgrade(child, command):
    '''
   /*****************************************************
    Function Name: utils_sys_upgrade
    Description : This function is being used to upgrade the image in the (Obu/Rsu).
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  utils rsu-upgrade -n { image name }

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : utils rsu-upgrade -n { image name }
   ****************************************************/
    '''
    cp_img_sys_to_dev = "utils copy {0}:scp://{1}:{2}/{3} image:{3}".format(
        config.SYS_UNAME,
        config.SYS_HOST,
        config.PATH,
        config.IMG_NAME)
    data = scp_command_cli(child, cp_img_sys_to_dev)
    if(re.search(b"successfully", data, re.I)):
        print(data)
        upgrade = command + " " + config.IMG_NAME
        print("Sending upgrade command:{}".format(upgrade))
        child.sendline("{}\r".format(upgrade))
        sleep(240)
        return 1
    else:
        print("not " + data)
        print("Run the test case once again")
        return 0


def utils_reboot(child, command):
    '''
   /*****************************************************
    Function Name: utils_reboot
    Description : This function is being used to reboot the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   utils reboot

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : utils reboot
   ******************************************************/
   '''
    try:
        child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
        child.sendline("{}\r".format(command))
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def utils_standby(child, command):
    '''
   /*****************************************************
    Function Name: utils_standby
    Description : This function is being used to halt the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  utils standby

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : utils standby
   ******************************************************/
   '''
    try:
        child.expect(config.CLIPMT)
        child.sendline("{}\r".format(command))
        child.expect(config.CLIPMT)
        data = child.before
        data = str(data)
        print(data)
        # child.sendline("\r")
        # sleep(30)
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in utils standby..")
        return 0


def utils_run(child, command, immediate=None):
    '''
   /*****************************************************
    Function Name: utils_run
    Description : This function is being used to run the system.
                 (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   run

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : run
   ******************************************************/
   '''
    try:
        child.expect(config.CLIPMT)
        child.sendline("{}\r".format(command))
        if immediate:
            print("Immediate return requested")
            return None
        child.expect(config.CLIPMT, timeout=90)
        data = child.before
        # child.sendline("\r")
        data = str(data)
        # sleep(30)
        print(data)
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in utils run..")
        return 0


def utils_reboot_status(child, command):
    '''
   /*****************************************************
    Function Name: utils_reboot_status
    Description : This function is being used to  retrieve the reboot status of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  utils reboot status

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : utils reboot status
   ******************************************************/
   '''
    # We needed reboot status.
    data = run_command_show(child, command)
    data_list = data.split("\n")
    return data_list[1]


def utils_reset(child, command):
    '''
   /*****************************************************
    Function Name: utils_reset
    Description : This function is being used to restore the factory version of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : utils reset factory-defaults

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : utils reset factory-defaults
    ******************************************************/
   '''
    child.sendline("")
    try:
        child.expect(config.CLIPMT)
        print("command:{}".format(command))
        child.sendline("{}\r".format(command))
        try:
            child.sendline("{}\r".format(command))
        except pexpect.EOF:
            return 1
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Time out...")
        return 0


def pr_enable(child, command, *args):
    '''
   /*****************************************************
    Function Name: pr_eanble
    Description : This function is being used to enter previliged mode from the shell mode in the rsu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  pr enable

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : pr enable
   ******************************************************/
    '''
    try:
        dev_lgn_dtils = config.RSU_Dict[args[0]]
        child.sendline("")
        child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
        if re.search(r"disable", command):
            child.sendline("{}".format(command))
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
            return 1
        child.sendline("{}".format(command))
        child.expect("password")
        print(child.before)
        child.sendline(dev_lgn_dtils["PR_PASSWORD"])
        child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
        data = child.before
        data = str(data, "utf-8")
        if re.search(r"incorrect", data, re.I):
            print(data)
            return 0
        child.sendline("\r")
        child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT))
        return 1
    except KeyError:
        print("Please provide valid device name. Returning None...")
        return None
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def shell_drop(child, command):
    '''
   /*****************************************************
    Function Name: shell_drop
    Description : This function is being used to enter previliged mode from the shell mode in the rsu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  shell-drop

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : shell-drop OR shell-drop
   ******************************************************/
   '''
    try:
        try:
            child.expect("{}|{}".format(config.CLIPMT,config.MODIFIED_CLIPMT), timeout=10)
        except pexpect.TIMEOUT:
            pass
        child.sendline("{}".format(command))
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def sys_process(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: sys_process
    Description : This function is being used to know the system current process.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  ps

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : ps
    Output :
            root@StreetWAVE:~# ps
  PID USER       VSZ STAT COMMAND
    1 root      1304 S    /sbin/procd
    2 root         0 SW   [kthreadd]
    3 root         0 SW   [ksoftirqd/0]
    5 root         0 SW<  [kworker/0:0H]
    7 root         0 SW   [rcu_sched]
    8 root         0 SW   [rcu_bh]
    9 root         0 SW   [migration/0]
   10 root         0 SW   [migration/1]
   11 root         0 SW   [ksoftirqd/1]
   13 root         0 SW<  [kworker/1:0H]
   14 root         0 SW<  [khelper]
  241 root         0 SW<  [writeback]
  244 root         0 SW<  [crypto]
  245 root         0 RW   [kworker/0:1]
  246 root         0 SW<  [bioset]
  248 root         0 SW<  [kblockd]
  334 root         0 SW   [kswapd0]
  338 root         0 SW   [fsnotify_mark]
  344 root         0 SW   [kworker/1:1]

   ******************************************************/
   '''
    try:
        command = None
        if len(args) is 2:
            command = cmd + " " + args[0]
            print("command:{}".format(command))
            index = args[1]
        else:
            command = cmd
        child.sendline("")
        child.expect(config.SHELLPMT)
        child.sendline("{}".format(command))
        child.expect(config.SHELLPMT)
        child.sendline("{}".format(command))
        child.expect(config.SHELLPMT)
        data = child.before
        # data = str(data, "utf-8")
        if len(args) > 0:
            try:
                data_clean1 = re.sub(b"\r+", b"", data)
                data_clean2 = re.split(b"\n", data_clean1)
                # In below pattern "root@" depends on SHELLPMT.
                # If it changes the pattern may change.
                data_clean3 = [line for line in data_clean2 if not
                               re.search(b"(grep)|(root@)", line)]
                data_clean3 = str(data_clean3[0]).strip()
                data_index = re.search(r"\d+", data_clean3).start()
                data_clean3 = data_clean3[data_index:]
                data_clean4 = re.sub(r"\s+", " ", data_clean3)
                final_data = re.split(r" ", data_clean4, 4)
                ret_val = final_data[int(index)]
                if ret_val.isnumeric():
                    ret_val = int(ret_val)
                return ret_val
            except IndexError:
                print("Process may not be running")
                return -1
        return str(data)
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def killall(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: killall
    Description : This function is being used to kill all process of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   killall StoreRepeat

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : killall StoreRepeat
    This function kill all the StoreRepeat process.
   ******************************************************/
    '''
    try:
        child.sendline("")
        child.expect(config.SHELLPMT)
        command = None
        if len(args) > 0:
            command = cmd + " " + args[0]
        else:
            command = cmd
        child.sendline("{}\r".format(command))
        child.expect(config.SHELLPMT)
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def clear_fun(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: clear_fun
    Description : This function is being used to clear the data shell prompt.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : clear

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : clear

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.SHELLPMT, timeout=5)
        child.sendline(cmd)
        child.expect(config.SHELLPMT, timeout=5)
        return 1
    except pexpect.TIMEOUT:
        try:
            child.sendline("\r")
            child.expect(config.CLIPMT)
            child.sendline("{}".format(cmd))
            child.expect(config.CLIPMT)
            return 1
        except pexpect.TIMEOUT:
            print("Failed to run 'clear' command")
            return 0


def rse_run_command(child, cmd):
    '''
   /*****************************************************
    Function Name: rse_run_command
    Description : This function is being used to run the command in the rsu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  rse run command

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : rse run command

   ******************************************************/
    '''
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline(cmd)
    child.expect(config.SHELLPMT)
    child.sendline(cmd)
    child.expect(config.SHELLPMT)
    data = child.before
    data = str(data, "utf-8")
    return data


def rse_stats(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: rse_stats
    Description : This function is being used to run the command starts with "rse_stats".
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : rse_stats -t

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : rse_stats -t
    Information of TIM(Tx, Channel, Udp Tx Packet).

   ******************************************************/
   '''
    if len(args) > 1:
        cmd = args[0]
        field = args[1]
    else:
        cmd = cmd.strip()
        field = args[0]
    print("command is:{}".format(cmd))
    data = rse_run_command(child, cmd)
    if data is None:
        print("Received None from rse_run_command")
        return 0
    print(data)
    data_lines = re.split(r"\n", data)
    print(data_lines)
    for line in data_lines:
        if re.search(field, line):
            values = re.split(":", line, 1)
            if not re.search(r"running", values[0], re.I):
                try:
                    print(line.strip())
                    return int(values[1].strip())
                except ValueError:
                    return values[1].strip()
            elif re.search(r"not running", values[1], re.I):
                print(cmd)
                print("not running")
                return 0  # BSM or IPV6 Data not running
            else:
                print(cmd)
                print("is running")
                return 1  # BSM or IPV6 Data is running


def cgps(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: cgps
    Description : This function is being used to know the cgps status of the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : cgps

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : cgps (current gps information)
    Output :
             Time, lat, lon, altitude etc.
   ******************************************************/
   '''
    slp = None
    if args:
        slp = int(args[0])
    else:
        slp = 2
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline("cgps")
    sleep(slp)
    child.sendcontrol("C")
    child.expect(config.SHELLPMT)
    sleep(5)
    data = str(child.before, "utf-8")
    print("****CGPS OUTPUT***")
    print(data)
    print("******************")
    mode = re.search(r"mode[\":\s]+([\d]+),", data)
    time = re.search(r'time[\":\s]+([\d]{4}\-[\d]{2}\-[\d]{2})T([\d]{2}\:[\d]{2}\:[\d]{2})\.000Z\"\,\"ept', data)
    if "time" in args:
        try:
            time = time.group(2)
            return time
        except AttributeError:
            print("No time string found")
            return -1  
    if "date" in args:
        try:
            date = time.group(1)
            return date
        except AttributeError:
            print("No date string found")
            return -1
    try:
        mode = mode.group(1)
        mode = int(mode)
        print("mode:{}".format(mode))
        if mode == 3:
            print("3D fix received")
            return "3D FIX"
        elif mode == 2:
            print("2D fix received")
            return "2D FIX"
        else:
            print("No fix received")
            return "NO FIX"
    except AttributeError:
        print("No fix received")
        return "NO FIX"


def reboot_func(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: reboot_func
    Description : This function is being used to reboot the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : reboot

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : reboot

   ******************************************************/
   '''
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline("reboot")
    return 1


def halt_run(child, command):
    '''
   /*****************************************************
    Function Name: halt_run
    Description : This function is being used to halt and run the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  halt;run

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : halt;run

   ******************************************************/
   '''
    try:
        child.sendline("{}".format(command))
        child.expect(config.SHELLPMT, timeout=60)
        halt_run_data = child.before
        halt_run_data = str(halt_run_data, "utf-8")
        print(halt_run_data)
        return halt_run_data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def exit_fun(child, command):
    '''
   /*****************************************************
    Function Name: exit_fun
    Description : This function is being used exit the cli mode in the Rsu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  exit

    Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : exit

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.SHELLPMT, timeout=7)
        child.sendcontrol("D")
        child.expect(config.CLIPMT)
        print(child.before)
        child.sendline("\r")
        child.expect(config.CLIPMT)
        print(child.before)
        print("entered into the CLI mode...")
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        child.expect(config.CLIPMT)
        child.sendline("exit\r")
        print("exited from the device")
        return 1


def sleep_fun(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: sleep_fun
    Description : This function is being used to sleep the system for some seconds.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  sleep(30)

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : sleep(30)

   ******************************************************/
   '''
    try:
        print("Going for sleep:{} sec".format(args[0]))
        sleep(int(args[0]))
        return 1
    except IndexError:
        print("Please provide the number of sec to sleep")
        print("Going to sleep by default 55 seconds")
        sleep(55)


def rsu_shell(child, cmd, *args):
    '''*****
   /*****************************************************
    Function Name: rsu_shell
    Description : This function is being used to sleep the system for some seconds.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  rsu shell

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : rsu shell

   ******************************************************/
   '''
    def func(x, y): return x + " " + y
    command = reduce(func, args)
    command = command.strip()
    print("command:{}".format(command))
    child.sendcontrol("C")
    child.expect(config.SHELLPMT)
    child.sendline("{}".format(command))
    child.expect(config.SHELLPMT, timeout=100)
    data = child.before
    data_str = str(data)
    return data_str


def rsu_ping_statistics(child, cmd, *args, count=5):
    '''
           /*****************************************************
            Function Name: rsu_ping_statistics
            Description : This function is being used to ping an ip address.
                          (refer api_wrapper.txt for associated commands with the API)
            Input Parameters :
            child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
            command  : obu ping {ipaddress,<ipaddress>,option,count}
                       obu ping6 {ipaddress,<ipaddress>,option,count}


             Return Value : Result of the command or Failure reason.
                           Data type: String

            Type : External API

            Example : rsu ping
            Output:
        PING 10.0.0.229 (10.0.0.229): 56 data bytes
        64 bytes from 10.0.0.229: seq=0 ttl=64 time=0.482 ms
        64 bytes from 10.0.0.229: seq=1 ttl=64 time=0.327 ms
        64 bytes from 10.0.0.229: seq=2 ttl=64 time=0.328 ms
        64 bytes from 10.0.0.229: seq=3 ttl=64 time=0.299 ms
        64 bytes from 10.0.0.229: seq=4 ttl=64 time=0.331 ms

        --- 10.0.0.229 ping statistics ---
        5 packets transmitted, 5 packets received, 0% packet loss
        round-trip min/avg/max = 0.299/0.353/0.482 ms

           ******************************************************/
        '''

    command = cmd.split("rsu")[1].strip()
    if args[0] == "ipaddress":
        ipaddress = args[1].split("/")[0]
    else:
        print("ipaddress not provided")
        return -1
    try:
        # count = args[0]
        option = args[2]
        # ip_address=kwargs['ip_address']
    except IndexError:
        option = 0
    child.sendline("")
    child.expect(config.SHELLPMT)
    child.sendline(
        "{} {}  -c {} > ping.txt".format(command, ipaddress, int(count)))
    sleep(int(count))
    child.expect(config.SHELLPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    file_copy(child, "file copy", "ping.txt")
    with open("{}/ping.txt".format(dest_path), "r") as ping:
        data = ping.read()
    if not data:
        print("Bad ip address provided")
        return -1

    data_dict = {
        'packets_transmitted': re.search(r"([\d]*)\s(packets transmitted)", data),
        'packets_recieved': re.search(r"([\d]*)\s(packets received)", data),
        'packetloss': re.search(r"([\d]*)%\spacket loss", data),
        'round_trip_min': re.search(r"round-trip min/avg/max = ([\d.]*)", data),
        'round_trip_avg': re.search(r"round-trip min/avg/max = .*\/([\d.]*)\/.*", data),
        'round_trip_max': re.search(r"round-trip min/avg/max = .*\/.*\/([\d.]*)", data)
    }

    if not option:
        print("No option provided, displaying ping output")
        print(data)
        return 0
    try:
        re_object = data_dict[option]
        value = re_object.group(1)
    except (KeyError, AttributeError):
        print("Please provide valid option or Pattern not found")
        return "-1"
    return int(value) if value.isnumeric() else value


def rsu_dmesg(child, command):
    '''
    /*********************************************************************
    Function Name: rsu_dmesg
            Description : This function is being used to run dmesg command in RSU.
                          (refer api_wrapper.txt for associated commands with the API)
            Input Parameters :
            child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
            command  : rsu dmesg
             Return Value : Result of the command or Failure reason.
                           Data type: String

    **************************************************************************/
    '''

    command = command.split("rsu")[1]
    child.sendline("")
    try:
        child.expect(config.SHELLPMT)
        child.sendline("{}\r".format(command))
        child.expect(config.SHELLPMT, timeout=120)
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
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        return None


def rsu_show_traceroute(child, command, ipaddress=None):
    '''
    /*********************************************************************
    Function Name: rsu_traceroute
            Description : This function is being used to run traceroute command in RSU.
                          (refer api_wrapper.txt for associated commands with the API)
            Input Parameters :
            child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
            command  : rsu traceroute
             Return Value : Result of the command or Failure reason.
                           Data type: String

    **************************************************************************/
    '''

    command = command.split("rsu")[1]
    command += f" {ipaddress}"
    child.sendline("")
    try:
        child.expect(config.CLIPMT)
        data = run_command_show(child, command)
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        return None


def rsu_utils_ping(child, command, *args):
    command = command.split("rsu")[1]
    command += f" {args[0]}"
    try:
        option = args[1]
    except:
        option = 0
    try:
        sleep(0.5)
        child.expect(config.CLIPMT)
        child.sendline("{}\r".format(command))
        child.expect(config.CLIPMT)
        data = child.before
        data = re.sub(r"\r", "", data.decode('utf-8'))
        data = re.sub(r"(\n)+", "\n", data)
        if not data:
            print("Bad ip address provided")
            return -1

        data_dict = {
            'packets_transmitted': re.search(r"([\d]*)\s(packets transmitted)", data),
            'packets_recieved': re.search(r"([\d]*)\s(packets received)", data),
            'packetloss': re.search(r"([\d]*)%\spacket loss", data),
            'round_trip_min': re.search(r"round-trip min/avg/max = ([\d.]*)", data),
            'round_trip_avg': re.search(r"round-trip min/avg/max = .*\/([\d.]*)\/.*", data),
            'round_trip_max': re.search(r"round-trip min/avg/max = .*\/.*\/([\d.]*)", data)
        }

        if not option:
            print("No option provided, displaying ping output")
            print(data)
            return 0
        try:
            re_object = data_dict[option]
            value = re_object.group(1)
        except (KeyError, AttributeError):
            print("Please provide valid option or Pattern not found")
            return "-1"
        return int(value) if value.isnumeric() else value
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        return None


def show_system_all(child, cmd):
    '''
            /*********************************************************************
            Function Name: show_system_all
                    Description : This function is being used to run show system ?
                    Input Parameters :
                    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
                    command  : show system ?
                     Return Value : Result of the command if no option is provided else returns param value.
                                   Data type: String
            **************************************************************************/
            '''
    data = run_command_show(child, cmd)
    if data is None:
        print("Received None and returning -1")
        return "-1"
    return data


def child_close(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: child_close
    Description : This function is being used to close the connection, Before closing the connection this function will change the board to US stack.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  child close

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : child close

   ******************************************************/
   '''
    # global _STACK
    global _logger_libRSE
    logger = _logger_libRSE
    try:
        device = args[0]
        print("DE:{}".format(device))
        if re.search("eu", device, re.I):
            child.sendline("")
            child.expect(config.OBUPMT)
            child.close(force=True)
            logger.info("Closed connection for {}".format(device))
            return 1
        if re.search("obu", device, re.I):
            print("Resetting OBU to default")
            # Here "obu reset" is command not a flag.
            obu_reset_func(child, "obu reset")
            child.close(force=True)
            logger.info("Closed connection for {}".format(device))
            return 1
        elif re.search("rsu", device, re.I):
            try:
                child.sendline("\r")
                child.expect(config.CLIPMT)
                # utils_reset(child, "utils reset application-configuration")
                # print("Resetting RSU to default")
                child.close(force=True)
                logger.info("Closed connection for {}".format(device))
                # sleep(60)
                return 1
            except pexpect.TIMEOUT:
                try:
                    child.expect(config.SHELLPMT)
                except pexpect.TIMEOUT:
                    print("Unable to reset the RSU")
                    print("Closing the connection")
                exit_fun(child, cmd)
                # utils_reset(child, "utils reset application-configuration")
                # print("Resetting RSU to default")
                child.close(force=True)
                # sleep(60)
                return 1
    except IndexError:
        print("No device name provided")
        print("Failed to reset the board to default")
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def obu_run_command(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_run_command
    Description : This function is being used to run the command in the OBU.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu sysupgrade -n

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu sysupgrade -n OR obu sysupgrade -c
              The above function is being used to upgarde the image in the OBU.


    ******************************************************/
   '''
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
        child.sendline("{}".format(command))
        sleep(2)
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


def obu_cat(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_cat
    Description : This function is being used to display the content.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu cat /etc/banner

     Return Value : Result of the command or Failure reason.
                    Data type: String

    Type : External API

    Example : obu cat /etc/banner
             The above command is being used to check which image is present in the system.


    ******************************************************/
   '''
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
        sleep(2)
        child.expect(config.OBUPMT, timeout=500)
        data = child.before
        data = str(data, "utf-8")
        sw_release = re.search(r"(SW_Release[\s:\w\d\.\-]+)URL", data, re.I)
        if sw_release:
            return sw_release.group(1)
        else:
            child.sendline("")
            child.expect(config.OBUPMT)
            child.sendline("{}".format(command))
            sleep(2)
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


def obu_scp(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_scp
    Description : This function is being used to copy the files from obu to PC.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu scp

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu scp

   ******************************************************/
   '''
    try:
        source = args[0]
        dest = args[1]
        command = None
        if re.search(r"resource", dest):
            dest = dest.split("resource")[1]
            command = "scp {0} {1}@{2}:{3}/resource{4}".format(source,
                                                               config.SYS_UNAME,
                                                               config.SYS_HOST,
                                                               config.SAFE_FW_PATH,
                                                               dest)
        else:
            command = "scp {} {}@{}:{}".format(source, config.SYS_UNAME,
                                               config.SYS_HOST, dest)
        print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("{}".format(command))
        try:
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting", timeout=5)
            child.sendline("y\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        sleep(2)
        child.expect(config.OBUPMT, timeout=1000)
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


def obu_scp_sys(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_scp
    Description : This function is being used to copy the image file from PC to obu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu scp sys

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu scp sys
     scp [-1246BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-P port] [-S program]
           [[user@]host1:]file1 [...] [[user@]host2:]file2


    ******************************************************/
   '''
    try:
        source = args[0]
        dest = args[1]
        if re.search(r"resource", source):
            source = source.split("resource")[1]
            command = "scp {0}@{1}:{2}/resource{3} {4}".format(config.SYS_UNAME,
                                                               config.SYS_HOST,
                                                               config.SAFE_FW_PATH,
                                                               source,
                                                               dest)
        else:
            command = "scp {}@{}:{} {}".format(config.SYS_UNAME, config.SYS_HOST,
                                               source, dest)
        print("Copying file:")
        print("{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("{}".format(command))
        try:
            child.expect("password:")
            #print("Expected password")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting", timeout=5)
            child.sendline("y\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        sleep(2)
        child.expect(config.OBUPMT, timeout=1000)
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


def obu_file_config(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_file_config
    Description : This function is being used to change the configarations in the config file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu file config

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu file config

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field_to_change = args[1]
            value = str(args[2])
            if len(args) > 3 and args[3] == 'space':
                delimiter = ' '
            else:
                delimiter = '='
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        if re.search(r"/", value):
            value = re.sub("/", r"\/", value)
            print(value)
        if value == "NULL":
            command = r"sed -i 's/^{0} *{1} *\"*[_\.\-\s:/0-9a-zA-Z]*\"*/{0}          = /g' \
                    {3}".format(field_to_change, delimiter, value, path)
        elif "\"" not in value:
            command = r"sed -i 's/^{0} *{1} *[_\.\-\s:/0-9a-zA-Z]*/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        else:
            command = r"sed -i 's/^{0} *{1} *\"[_\.\-\s:/0-9a-zA-Z]*\"/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        child.sendline(command)
        child.expect(config.OBUPMT)
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_change, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.OBUPMT)
        awk_data = str(child.before, "utf-8")
        print(awk_data)
        # [TODO] correct the code
        # awk_data_str = re.split(r"\n", awk_data)
        # conf_str = [line for line in awk_data_str if re.search(
        #    r"^{}".format(field_to_change), line)]
        # print(conf_str)
        # conf_val = re.search(r"=\s{0,}([\da-zA-Z]+)", conf_str[0]).group(1)
        # conf_val = conf_val.strip()
        # print(conf_val)
        # if value == conf_val:
        #    print("file successfully configured")
        #    return 1
        # else:
        #    print("file not successfully configured")
        #    return "-1"
        # child.sendline("")
        print("file successfully configured")
        return awk_data
    except IndexError:
        print("Please provide the valid number of arguments")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def obu_file_config_get(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_file_config
    Description : This function is being used to get the configarations in the config file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :ig
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu file config get

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu file config  get

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field_to_get = args[1]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_get, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.OBUPMT)
        awk_data = str(child.before, "utf-8")
        print(awk_data)
        awk_data_str = re.split(r"\n", awk_data)
        conf_str = [line for line in awk_data_str if re.search(
            r"^{}".format(field_to_get), line)]
        print(conf_str)
        conf_val = re.search(
            r'=\s{0,}"?([\da-zA-Z_.-\/]+)"?', conf_str[0]).group(1)
        conf_val = conf_val.strip()
        print(conf_val)
        return conf_val
    except IndexError:
        print("Please provide the valid argument to fetch")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def tap_data_to_dict(tap_msg):
    '''
   /*****************************************************
    Function Name: tap_data_to_dict
    Description : This function is being used by onother API to tap the messeage data in to key value pairs using regular expression.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  tap_data_to_dict

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : tap_data_to_dict

    ******************************************************/
   '''
    tap_msg_lines = re.split(r"\n", tap_msg)
    tap_msg_keys = [re.search(r"^([a-zA-Z\s]+):?", line)
                    for line in tap_msg_lines[1:-1]]
    tap_msg_values = [re.search(r":?[\s]+?([\d\.]+)", line)
                      for line in tap_msg_lines[1:-1]]
    tap = {}
    for key, value in zip(tap_msg_keys, tap_msg_values):
        try:
            tap[key.group(1).strip()] = value.group(1)
        except AttributeError:
            tap[key.group(1).strip()] = None
    return tap


def obu_v2x_wsmptap_bsm(child, *args):
    '''
   /*****************************************************
    Function Name: obu_v2x_wsmptap_bsm
    Description : This function is being used to spilt  BSM message  from the wsmp to key value pair.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu v2x wsmptap bsm

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu v2x wsmptap bsm

    ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("v2x_wsmptap -d tap.txt\r")
        sleep(2)
        child.sendcontrol("c")
        child.expect(config.OBUPMT)
        child.sendline("cat tap.txt")
        child.expect(config.OBUPMT)
        wsm_messy_data = child.before
        child.sendline("rm tap.txt")
        child.expect(config.OBUPMT)
        child.sendcontrol("c")
        return wsm_messy_data
        wsm_messy_data = str(wsm_messy_data, "utf-8")
        wsm_clean_data = re.sub(r"\t+", "", wsm_messy_data)
        bsm = re.finditer("BSM", wsm_clean_data)

        bsm_start = [msg.start() for msg in bsm]
        for i in range(0, 1):
            bsm_msg = wsm_clean_data[i:bsm_start[i + 1]]
            bsm_msg_lines = re.split(r"\n", bsm_msg)
            bsm_msg_keys = [re.search(r"^([a-zA-Z\s]+):?", line)
                            for line in bsm_msg_lines[1:-1]]
            bsm_msg_values = [re.search(r":?[\s]+?([\d\.]+)", line)
                              for line in bsm_msg_lines[1:-1]]
        bsm = {}
        for key, value in zip(bsm_msg_keys, bsm_msg_values):
            try:
                bsm[key.group(1)] = value.group(1)
            except AttributeError:
                bsm[key.group(1)] = None
        return bsm[args[0]]
    except pexpect.TIMEOUT:
        print("Time out...")
        return None
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Check your internet connection")
        return None


def obu_v2x_wsmptap_tim(child, command, *args):
    '''
   /*****************************************************
    Function Name: obu_v2x_wsmptap_tap
    Description : This function is being used to spilt  TIM message  from the wsmp to key value pair.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu v2x wsmptap tim

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu v2x wsmptap tim

    ******************************************************/
   '''
    if len(args) < 2:
        print("Insufficient arguments to process")
        print("usage <unique ID> <TIM field>")
        return 0
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("v2x_wsmptap -d tap.txt\r")
        sleep(3)
        child.sendcontrol("c")
        child.expect(config.OBUPMT)
        child.sendline("cat tap.txt")
        sleep(2)
        child.expect(config.OBUPMT)
        wsm_messy_data = child.before
        child.sendline("rm tap.txt")
        child.expect(config.OBUPMT)
        child.sendcontrol("c")
        wsm_messy_data = str(wsm_messy_data, "utf-8")
        wsm_clean_data = re.sub(r"\t+", "", wsm_messy_data)
        uni_id = re.search("{}".format(args[0]), wsm_clean_data)
        if not uni_id:
            print("No message with the given UniqueMessageId")
            print("Returning zero...")
            return 0
        uni_id_index = uni_id.start()
        print("uni_id_index:{}".format(uni_id_index))
        tim_data_start_find = uni_id_index - 100
        print("tim_data_start_find:{}".format(tim_data_start_find))
        if tim_data_start_find < 0:
            tim = re.search(r"TIM", wsm_clean_data)
            tim_index = tim.start()
        else:
            tim = re.search(r"TIM", wsm_clean_data[tim_data_start_find:])
            tim_index = tim.start() + uni_id_index - 100
        if not tim:
            print("No TIM messages found")
            print("Returning zero...")
            return 0
        print("tim_index:{}".format(tim_index))
        spat_bsm = re.search(r"(SPAT)|(BSM)|(TIM)",
                             wsm_clean_data[tim_index + 1:])
        if not spat_bsm:
            print("no spat or bsm or tim found")
            print("Returning zero...")
            return 0
        spat_bsm_index = tim_index + spat_bsm.start()
        tim_msg = wsm_clean_data[tim_index:spat_bsm_index]
        tim_dict = tap_data_to_dict(tim_msg)
        try:
            return tim_dict[args[1]]
        except KeyError:
            print("KeyError...")
            return tim_dict
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Time out happened in obu_v2x_wsmptap_tim...")
        return None


def obu_v2vspidemo(child, cmd):
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("v2vspidemo > test.txt\r")
        sleep(3)
        # sending up arrow escape chracter ("\x1B[A") for capturing the output
        child.sendline("\x1B[A")
        child.expect(config.OBUPMT)
        child.sendline("cat test.txt")
        sleep(2)
        child.expect(config.OBUPMT)
        v2vspidemo_output = child.before
        child.sendline("rm test.txt")
        child.expect(config.OBUPMT)
        child.sendcontrol("c")
        v2vspidemo_output = str(v2vspidemo_output, "utf-8")
        print(v2vspidemo_output)
        return v2vspidemo_output
    except pexpect.TIMEOUT:
        print("Time out happened in obu_v2vspidemo...")
        return None


def obu_cgps(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_cgps
    Description : This function is being used to know the status of the gps in the obu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu cgps

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu cgps

   ******************************************************/
   '''
    slp = None
    if args:
        slp = int(args[0])
    else:
        slp = 5
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("gpspipe -w\r")
    sleep(slp)
    child.sendcontrol("c")
    child.expect(config.OBUPMT)
    sleep(5)
    data = str(child.before, "utf-8")
    data = re.split(r"\n", data)
    for i in data:
        if re.search(r"\"class\":\"TPV\"", i, re.I):
            data = i
            break
    print(data)
    mode = re.search(r"mode[\":\s]+([\d]+),", data)
    try:
        mode = mode.group(1)
    except AttributeError:
        print("No mode found")
        return "NO MODE"
    mode = int(mode)
    lat = re.search("lat[\":]+([\d\.]+),", data)
    lon = re.search("lon[\":]+([\d\.]+),", data)
    alt = re.search("alt[\":]+([\d\.]+),", data)

    try:
        if mode == 3:
            # print("Mode:{}".format(mode))
            print("Latitude:{}".format(lat.group(1)))
            print("Longitude:{}".format(lon.group(1)))
            print("Elevation:{}".format(alt.group(1)))
            return "3D FIX"
        elif mode == 2:
            # print("Mode:{}".format(mode))
            print("Latitude:{}".format(lat.group(1)))
            print("Longitude:{}".format(lon.group(1)))
            return "2D FIX"
        else:
            # print("Mode:{}".format(mode))
            print(data)
            print("No fix received")
            return "NO FIX"
    except AttributeError:
        print("No fix received")
        return "NO FIX"


def obu_top(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_top
    Description : This function is being used to know top 20 process in the board.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu top

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu top
    Output:
            PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
 2076     1 root     S <   3676   0%   4% gpsd -b /dev/ttymxc1
  731     2 root     SW       0   0%   2% [kworker/0:0]
 1705     2 root     SW       0   0%   1% [AR6K Async]
 1761     2 root     SW       0   0%   1% [AR6K Async]
 2999     1 root     S    28688   2%   1% /usr/local/bin/AeroLinkv2xd.bin
 3023     1 root     S     2748   0%   1% /usr/local/bin/savari16093d
  558     2 root     SW       0   0%   1% [irq/57-mmc3]
  543     2 root     SW       0   0%   0% [irq/54-mmc0]
 3031     1 root     S    11524   1%   0% /usr/local/bin/BSMd -i /etc/config/ -
 1718 32647 root     R     1308   0%   0% top
32646  2442 root     S     1100   0%   0% /usr/sbin/dropbear -F -P /var/run/dro
 1669     1 root     S      980   0%   0% /usr/sbin/chronyd -n -f /var/etc/chro
  344     2 root     SW       0   0%   0% [kworker/1:1]
    7     2 root     SW       0   0%   0% [rcu_sched]
 2394     1 root     S    76596   4%   0% /usr/bin/pulseaudio -D --realtime=fal
 2992     1 root     S     3396   0%   0% /usr/bin/savpkiconnd
 2185     1 root     S     3204   0%   0% /usr/local/bin/savariaudio-app -s 441
 2373     1 root     S     3048   0%   0% /usr/bin/bluetoothd -n
 2034     1 root     S     1936   0%   0% /usr/local/bin/smgrd
 2107     1 root     S     1880   0%   0% /usr/loc/bin/v2x_installer


   ******************************************************/
   '''
    try:
        if not args:
            field = 0
        else:
            field = args[0]
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("top\r")
        sleep(3)
        child.sendcontrol("c")
        child.expect(config.OBUPMT)
        top_data = str(child.before, "utf-8")
        if not field:
            print(top_data)
            return 1
        keys = re.findall(r"\s+%?([a-zA-Z]+)", top_data.split("\n")[4])
        top_data_lines = re.split(r"\n", top_data)
        data = [line for line in top_data_lines if re.search(
            field, line, re.I)]
        data = re.sub(r"(\s)+", " ", data[0])
        values = re.findall(r"\s+[a-zA-Z\d.]+", data)
        data_dict = {k.strip(): v.strip() for k, v in zip(keys, values)}
        try:
            stat_val = args[1]
            return data_dict[stat_val]
        except IndexError:
            print("Provide a field to be fetched")
            return -1
        except KeyError:
            print("Provide valid field to be fetched")
            return -1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None


def obu_ps(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_ps
    Description : This function is being used to know the process status of the obu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu ps

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu ps
    Output:
           PID   USER       VSZ STAT COMMAND
            1    root      1304 S    /sbin/procd
            2    root         0 SW   [kthreadd]
            3    root         0 SW   [ksoftirqd/0]
            5    root      0 SW<  [kworker/0:0H]
            7    root         0 SW   [rcu_sched]
            8    root         0 SW   [rcu_bh]
            9    root         0 SW   [migration/0]
           10    root         0 SW   [migration/1]


   ******************************************************/
    '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("ps\r")
        sleep(2)
        child.expect(config.OBUPMT)
        ps_data = str(child.before, "utf-8")
        print(ps_data)
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None


def obu_df(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_df
    Description : This function is being used to know disk usage.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu ps

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu df
    Output:
          Filesystem           1K-blocks     Used    Available   Use% Mounted on
          rootfs               116668        89140     25084     78% /
         /dev/root             116668        89140     25084     78% /
          tmpfs                902420        104      902316      0% /tmp
       /dev/mmcblk0p3          3508496       10052    3300508     0% /nojournal
        tmpfs                  512           0         512        0% /dev
   ******************************************************/
   '''
    try:
        try:
            mount_system = args[0]
        except:
            mount_system = None
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("df -h\r")
        sleep(2)
        child.expect(config.OBUPMT)
        ps_data = str(child.before, "utf-8")
        print(ps_data)
        if mount_system:
            keys = re.findall(r"([a-zA-Z]+)", ps_data.split("\n")[1])
            data = [line for line in ps_data.split(
                "\n") if re.search(mount_system, line, re.I)]
            values = re.findall(r"[a-z\d./]+", data[0])
            data_dict = {k.strip(): v.strip() for k, v in zip(keys, values)}
            try:
                field = args[1]
                return data_dict[field]
            except IndexError:
                print("Provide a field to be fetched")
                return -1
            except KeyError:
                print("Provide valid field to be fetched")
                return -1
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None


def obu_mpstat(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_mpstat
    Description : This function is being used *****************************
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu mpstat

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu mpstat
    Output:
    Linux 3.18.29 (US16SIQC)   06/06/18   _armv7l_   (2 CPU)

   10:34:42     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest   %idle
   10:34:42     all    2.69    0.00    8.68    0.00    0.00    0.51    0.00    0.00   88.10
   ******************************************************/
   '''
    try:
        option = args[0]
    except IndexError:
        option = None
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("mpstat")
        sleep(2)
        child.expect(config.OBUPMT)
        ps_data = str(child.after, "utf-8")
        print(ps_data)
        keys = re.findall(r"\s+%?([a-zA-Z]+)", ps_data.split("\n")[2])
        values = re.findall(r"\s+[a-z\d.]+", ps_data.split("\n")[3])
        data_dict = {k.strip(): v.strip() for k, v in zip(keys, values)}
        # print(data_dict)
        if option:
            return data_dict[option]
        else:
            return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None


def obu_free(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_free
    Description : This function is being used to know free space in the device memory.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu free

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu free
    Output:
           total         used         free       shared      buffers
Mem:       1804844        47588      1757256          124          412
-/+ buffers:              47176      1757668
Swap:            0            0            0



   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("free\r")
        sleep(2)
        child.expect(config.OBUPMT)
        ps_data = str(child.before, "utf-8")
        print(ps_data)
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None
    return 1

# [TODO] Not Completed


def obu_file_config_2(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu ************************
    Description : This function is being used to know disk usage.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu ps

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu df
    Output:
          **********************


   ******************************************************/
   '''
    try:
        path = args[0]
        field_to_change = args[1]
        value = args[2]
    except IndexError:
        print("Please provide valid arguments <option> <path>")
        return "-1"
    child.sendline("")
    child.expect(config.OBUPMT)
    if re.search(r"/", value):
        value = re.sub("/", r"\/", value)
        print(value)
    if path in "/etc/config/syslog":
        value = "'{}'".format(value)
    if "\"" not in value:
        command = r"sed -i 's/^{0} *[_\.\-\s:/'0-9a-zA-Z]*/{0}  {1}/g' {2}".format(
            field_to_change, value, path)
    else:
        command = r"sed -i 's/^{0} *\"[_\.\-\s:/0-9a-zA-Z]*\"/{0}  {1}/g' {2}".format(
            field_to_change, value, path)
    print(command)
    child.sendline(command)
    child.expect(config.OBUPMT)
    print(str(child.before, "utf-8"))


def obu_syslog_config(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_syslog_config
    Description : This function is being used change the configuartion in the syslog file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu syslog config

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu syslog config { value }




   ******************************************************/
   '''
    try:
        path = args[0]
        field_to_change = args[1]
        value = str(args[2])
    except IndexError:
        print("Please provide valid arguments <option> <path>")
        return "-1"
    child.sendline("")
    child.expect(config.OBUPMT)
    if re.search(r"/", value):
        value = re.sub("/", r"\/", value)
        print(value)
    value = r"\'{}\'".format(value)
    print(value)
    command = r"sed -i {3}s/{0}[ \t]*[_\.\-\s:/'0-9a-zA-Z]* *'/{0}  {1}/g{3} {2}".format(
        field_to_change, value, path, "\"")
    print(command)
    child.sendline(command)
    child.expect(config.OBUPMT)
    awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_change, "print", path)
    child.sendline(awk_cmd)
    child.expect(config.OBUPMT)
    awk_data = str(child.before, "utf-8")
    print(awk_data)
    return 1

def obu_gpsd_config(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_gpsd_config
    Description : This function is being used change the GPS frequency(update rate) in the gpsd_init file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu gpsd config

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu gpsd config {/etc/init.d/gpsd_init, -u, 500}




   ******************************************************/
   '''
    try:
        path = args[0]
        field_to_change = args[1]
        value = args[2]
    except IndexError:
        print("Please provide valid arguments <option> <path>")
        return "-1"
    child.sendline("")
    child.expect(config.OBUPMT)
    print(value)
    command = r"sed -i {3}s/UBXDEVICE {0} [0-9]*/UBXDEVICE {0} {1}/g{3} {2}".format(
        field_to_change, value, path, "\"")
    #sed -i 's/UBXDEVICE -u [0-9]*/UBXDEVICE -u 200/g' /etc/init.d/gpsd_init
    print(command)
    child.sendline(command)
    child.expect(config.OBUPMT)
    awk_cmd = "awk '/UBXDEVICE {}/ {{{}}}' {}".format(field_to_change, "print", path)
    child.sendline(awk_cmd)
    child.expect(config.OBUPMT)
    awk_data = str(child.before, "utf-8")
    print(awk_data)
    return 1


def obu_get_newer_pcap_file(child, cmd, *args, file_copy=None):
    '''
   /*****************************************************
    Function Name: obu_get_newer_pcap_file
    Description : This function is being used to get the captured PCAP(network packets) files.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu get newer pcap file

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu get newer pcap file
   ******************************************************/
    '''
    extension = ""
    try:
        path = args[0]
        extension = args[1] if len(args) > 1 else ""
        dest_path = args[2] if len(args) > 2 else ""
    except IndexError:
        print("Please provide the path name")
        return "-1"
    path = os.path.abspath(path)
    command = "ls -rt {}/*.pcap | tail -n 1".format(path)
    print(command)
    child.sendline(command)
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    print(data)
    pcaplog = re.search(r"({}\.)?\d[\._\w]+pcap".format(extension), data)
    try:
        pcaplog_name = pcaplog.group()
    except AttributeError:
        print("No pcaplog found")
        return "-1"
    if file_copy:
        obu_scp(child, "obu scp", path + "/" + pcaplog_name, dest_path)
    return pcaplog_name


def obu_get_newer_syslog_file(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_get_newer_pcap_file
    Description : This function is being used to get the latest log files.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu get newer syslog file

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu get newer syslog file
   ******************************************************/
    '''
    try:
        path = args[0]
    except IndexError:
        print("Please provide the path name")
        return "-1"
    path = os.path.abspath(path)
    command = "ls -ltr {}/syslog* | tail -n 1".format(path)
    child.sendline(command)
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    print(data)
    syslog = re.search(r"syslog[_\d]*\.txt", data)
    try:
        syslog_name = syslog.group()
    except AttributeError:
        print("No syslog found")
        return "-1"
    return syslog_name


def obu_get_older_syslog_file(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_get_newer_pcap_file
    Description : This function is being used to get the latest log files.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu get newer syslog file

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu get newer syslog file
   ******************************************************/
    '''
    if args[1]:
        position = args[1]
    else:
        position = 1
    try:
        path = args[0]
    except IndexError:
        print("Please provide the path name")
        return "-1"
    path = os.path.abspath(path)
    command = "ls -ltr {}/syslog* | head -n {} | tail -n 1".format(
        path, position)
    child.sendline(command)
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    print(data)
    syslog = re.search(r"syslog[_\d]*\.txt", data)
    try:
        syslog_name = syslog.group()
    except AttributeError:
        print("No syslog found")
        return "-1"
    return syslog_name


def obu_get_last_syslog_size(child, cmd, *args):
    listoutput = []
    try:
        path = args[0]
    except IndexError:
        print("Please provide the path name")
        return "-1"
    path = os.path.abspath(path)
    command = "ls -lhtr {}/syslog* | tail -n 4".format(path)
    child.sendline(command)
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    data = data.split("\n")
    data = data[1:]
    data.pop()
    print(data)
    try:
        for line in data:
            data = line.split()
            size = re.search(r"root\s+root\s+(\d+)", line).group(1)
            size = size.split(".")
            size = int(size[0])
            listoutput.append(size)
        print(listoutput)
    except AttributeError:
        print("No syslog found")
        return "-1"
    return listoutput


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


def obu_halt_run(child, cmd):
    command = cmd.split("obu")[1].strip()
    child.sendline("")
    child.expect(config.OBUPMT)
    child.before
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT, timeout=100)
    halt_run_data = child.before
    halt_run_data = str(halt_run_data, "utf-8")
    print(halt_run_data)
    if halt_run_data is None:
        print("Received None from obu_run_command")
        return "-1"
    print(halt_run_data)
    return halt_run_data


def euobu_halt_run(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: euobu_halt_run
    Description : This function is being used to halt and run the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   euobu halt;run

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : euobu halt;run
   **********************************/
   '''
    """ Author: Nilesh Guhe
    """

    command = cmd.split("obu")[1].strip()
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    sleep(5)
    child.expect(config.OBUPMT, timeout=100)
    halt_run_data = child.before
    halt_run_data = str(halt_run_data, "utf-8")
    print(halt_run_data)
    if len(args) > 0:
        sleep(int(args[0]))
    child.sendcontrol("C")
    child.expect(config.OBUPMT)
    halt_run_data1 = child.before
    halt_run_data1 = str(halt_run_data1, "utf-8")
    print(halt_run_data1)
    run_data = halt_run_data + halt_run_data1
    if run_data is None:
        print("Received None from obu_run_command")
        return "-1"
    else:
        return run_data


def obu_asd_stats(child, command, *args, app=None):
    '''
   /*****************************************************
    Function Name:obu_asd_stats
    Description : This function is being used to know the applications status in th board.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  asd_stats -a

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : asd_stats -a
    Output:
    root@US16SIQC:~# asd_stats -a
BSM Data:
                Running: Running
                Signing Enabled:	0
                Num Tx:			0
                Num Rx:			0
                Num Signing Fail:	0
                Num Verify Fail:	0
                cur tx channel:		172
                Prerecord replays:	0
                Verification Failed but parsed:	0
                Num Encode Fail:	0
                Num Decode Fail:	0
                Rx Dropped due to security mismatch:	0
                Cert change count:	0
                Num RVs:		0
                Last tx/rx timestamp:	01/01/1970-00:00:00

TIM data:
                Num Rx:			0
                Num Decode Fail:	0
                Num Verify Fail:	0
                Rx Dropped due to security mismatch:	0

SPATMAP Data:
                Num Rx:			0
                Num Decode Fail:	0
                Num Verify Fail:	0
                Rx Dropped due to security mismatch:	0

PSM Data:
                Num Tx:			0
                Num Encode Fail:	0
                Num Signing Fail:	0

                Num Rx:			0
                Num Decode Fail:	0
                Num Verify Fail:	0

EVA Data:
                Num Tx:			0
                Num Encode Fail:	0
                Num Signing Fail:	0

                Num Rx:			0
                Num Decode Fail:	0
                Num Verify Fail:	0

SRM Data:
                Num Tx:			0
                Num Encode Fail:	0
                Num Verify Fail:	0

SSM Data:
                Num Denied Requests:	0
                Num Granted Requests:	0
                Num Rx:			0
                Num Verify Fail:	0
                Num Decode Fail:	0

RSA Data:
                Num Tx:			0
                Num Encode Fail:	0
                Num Signing Fail:	0

                Num Rx:			0
                Num Decode Fail:	0
                Num Verify Fail:	0

IPv6 Data:
                Running: Running
                Current Service channel:	0
                connected RSE mac:	00:00:00:00:00:00
                provider service context:
                advertiser id:
                Time of Connection:	01/01/1970-00:00:00
                Time of Disconnection:	01/01/1970-00:00:00


   *************************************************/
    '''
    if len(args) > 1:
        cmd = args[0]
        field = args[1]
    else:
        cmd = re.split(r"obu", command, 1)[1]
        cmd = cmd.strip()
        field = args[0]
    print("command is:{}".format(cmd))
    data = obu_run_command(child, cmd)
    if data is None:
        print("Received None from obu_run_command")
        return -1
    print_to_log(data)
    if app:
        data = re.split(app, data)[1]
    data_lines = re.split(r"\n", data)
    for line in data_lines:
        if re.search(field, line):
            values = re.split(":", line, 1)
            if not re.search(r"running", values[0], re.I):
                try:
                    print(line.strip())
                    op = int(values[1].strip())
                    return op if op is not None else -1
                except ValueError:
                    op = values[1].strip()
                    return op if op is not None else -1
            elif re.search(r"not running", values[1], re.I):
                print(cmd)
                print("not running")
                return 0  # BSM or IPV6 Data not running
            else:
                print(cmd)
                print("is running")
                return 1  # BSM or IPV6 Data is running


def obu_clear_fun(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_clear_fun
    Description : This function is being used to clear the data in the current shell prompt in the OBU.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu clear fun

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu clear fun

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.CLIPMT)
        child.sendline(cmd)
        child.expect(config.CLIPMT, timeout=5)
        return 1
    except pexpect.TIMEOUT:
        print("Failed to run 'clear' command")
        return 0


def obu_cp_func(child, command, *args):
    '''
   /*****************************************************
    Function Name: obu_cp_func
    Description : This function is being used to copy the file from source path to the destination path.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu cp

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu cp {'?', '?'}

   ******************************************************/
    '''
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        source_path = os.path.abspath(args[0])
        dest_path = os.path.abspath(args[1])
        child.sendline("cp {0} {1}/".format(source_path, dest_path))
        child.expect(config.OBUPMT)
        data = child.before
        data = str(data, "utf-8")
        print(data)
        print("Taken backup of {0} to {1}".format(source_path, dest_path))
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("timeout...")
        return None


def obu_reset_func(child, cmd, flag=None):
    '''
   /*****************************************************
    Function Name: obu_reset_func
    Description : This function is being used to reset all the configuaration values in to the default values in the config file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu_reset_func

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : obu_reset_func {"optional"} flag is optional

   ******************************************************/
   '''
    child.sendline("")
    child.expect(config.OBUPMT)
    child.before
    child.sendline("ls /nojournal/")
    child.expect(config.OBUPMT)
    data = child.before
    checkPrompt = str(child.after, "utf-8")
    if flag:
        if re.search(b"config.safe", data):
            child.sendline("rm -rf /nojournal/config.safe/")
        if re.search(b"configETSI.safe", data):
            child.sendline("rm -rf /nojournal/configETSI.safe/")
        child.sendline("mkdir /nojournal/config.safe")
        child.expect(config.OBUPMT)
        child.sendline("cp -r /etc/config/* /nojournal/config.safe/")
        return 1
    if not re.search(r"EU16SIQC", checkPrompt):
        child.sendline("cp -r /nojournal/config.safe/* /etc/config")
        child.expect(config.OBUPMT)
        data = str(child.before, "utf-8")
        print(data)
        obu_halt_run(child, "obu halt")
        sleep(3)
        obu_halt_run(child, "obu run")
        sleep(2)
        if re.search(r"No such file or directory", data):
            print("Unable to reset. Backup files may not exist")
            return 0
        print("OBU config files are in reset mode")
    return 1


def obu_shell_exec(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_shell_exec
    Description : This function is being used to execute the commands in the obu shell.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu_shell_exec

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : obu_shell_exec

   ******************************************************/
   '''
    def func(x, y): return x + " " + y
    command = reduce(func, args)
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT)
    data = str(child.before, "utf-8")
    return data


# This API just executes the given command, doesn't return anything
def obu_general_command(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_general_command
    Description : This function is being used to execute the general commands in the obu shell.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu general command

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu general command {ls}

    ******************************************************/
    '''
    try:
        "Author: Manasa Dosapati"
        command = str()
        if len(args) != 0:
            for arg in args:
                command = command + " " + arg
        print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("{}".format(command))
        child.expect(config.OBUPMT, timeout=500)
        child.sendline("{}".format(command))
        sleep(2)
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
        print("Timeout happened while executing \"{}\"".format(command
                                                               ))
        return None


def obu_general_command_with_pipe(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_general_command with pipe
    Description : This function is being used to execute the general commands in the obu shell.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu general command with pipe

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu general command with pipe {grep | abc}

    ******************************************************/
    '''
    try:
        command = str()
        if len(args) != 0:
            for arg in args[:-1]:
                command += arg + " | "
        command += args[-1]
        print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline("{}".format(command))
        sleep(2)
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


# This API just executes the given command, doesn't return anything
def general_command(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_general_command
    Description : This function is being used to execute the general command.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  general command

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : general command {rm, file_name}

   ******************************************************/
   '''
    try:
        command = str()
        if len(args) != 0:
            for arg in args:
                command = command + " " + arg
        print("general command:{}".format(command))
        child.sendline("")
        child.expect(config.SHELLPMT)
        child.sendline("{}".format(command))
        child.expect(config.SHELLPMT, timeout=500)
        sleep(2)
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
        print("Timeout happened while executing \"{}\"".format(command
                                                               ))
        return None


def obu_wmectl(child, cmd, *args):
    '''***********************
   /*****************************************************
    Function Name: obu_wmectl
    Description : This function is being used to run wmectl in the obu.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu wmectl -W

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu wmectl -W OR obu wmectl -r OR obu wmectl -s


   ******************************************************/
   '''

    def wmectl_W(child, cmd, *args):
        option = args[0]
        command = "{} {}".format(cmd, option)
        data = obu_run_command(child, command)
        return data

    def wmectl_r(child, cmd, *args):
        radio = args[0]
        if radio == "0":
            radio = "Radio [0]"
        elif radio == "1":
            radio = "Radio [1]"
        option = args[1]
        command = cmd
        data = obu_run_command(child, command)
        data = re.sub(r"\r", "", data)
        radio = re.escape(radio)
        pos = re.search(radio, data).end()
        data = data[pos:].split("\n")
        for line in data:
            if re.search(option, line):
                return line.split(":")[1].strip()

    def wmectl_s(child, cmd, mac=None, option=None):
        command = None
        if re.search(r"obu", cmd, re.I):
            command = cmd.split("obu")[1].strip()
        command = "{} > wmectl_s.txt".format(command)
        #data = obu_run_command(child, command)
        print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline(command)
        sleep(1)
        child.sendcontrol("C")
        child.expect(config.OBUPMT)

        dest_path = os.path.abspath(config.SAFE_FW_PATH)
        print("DEST_PATH:{}".format(dest_path))
        dest_path = "{}/resource/files".format(dest_path)
        obu_scp(child, "obu scp", "wmectl_s.txt", dest_path)
        with open("{}/wmectl_s.txt".format(dest_path), "r") as wmectl_s:
            data = wmectl_s.read()
        if mac:
            mac = mac.lower()
            data_dict={}
            list = re.findall("Entry([^>]*?--\n)",data)
            for ent in list:
                MAC = re.search("MAC\:\s*((([\da-fA-F]){2}:?){6})", ent).group(1)
                data_dict[MAC] = {
                    "WSA count": re.search(r"WSA count\s*(\d+)", ent).group(1),
                    "Latitude": re.search(r"Latitude\s*([\.\d]+)", ent).group(1),
                    "Longitude": re.search(r"Longitude\s*([\.\d]+)", ent).group(1),
                    "rssi": re.search(r"rssi\s*([\-\d]+)", ent).group(1),
                    "Verification count": re.search(r"Verification count\s*(\d+)", ent).group(1),
                    "Verification failure count": re.search(r"Verification failure count\s*(\d+)", ent).group(1),
                    "Advertiser ID": re.search(r"Advertiser ID\s*([A-Za-z0-9_]+)", ent).group(1)
                }
            if option:
                return data_dict[mac][option]
            else:
                try:
                    ret_data = data_dict[mac]
                    return (ret_data)
                except KeyError:
                    print ("Given mac {} is not found..".format(mac))
                    return -1
                return data_dict[mac]
        else:
            return data

    wmectl_dict = {"obu wmectl -W": wmectl_W,
                   "obu wmectl -r": wmectl_r,
                   "obu wmectl -s": wmectl_s}
    return wmectl_dict[cmd](child, cmd, *args)


def obu_acfinfo(child, cmd, *args):
    return
# Not implemented yet
# ******************************************


def obu_reboot_func(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_reboot_func
    Description : This function is being used to reboot the OBU.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   obu reboot

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu reboot


   ******************************************************/
   '''
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("reboot")
    data = child.readlines()
    data = [line.decode("utf-8") for line in data]
    data = "\n".join(data)
    print(data)
    return data


def obu_ifconfig(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_ifconfig
    Description : This function is being used to know the inforamation of thr system interface.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu ifconfig

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu ifconfig
    Output:
    root@US16SIQC:~# ifconfig
ath0      Link encap:Ethernet  HWaddr 09:AB:7A:C9:00:22
          inet6 addr: fe80::bab:7aff:fec9:22/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1492  Metric:1
          RX packets:3317801 errors:0 dropped:3022823 overruns:0 frame:0
          TX packets:1810 errors:0 dropped:9 overruns:0 carrier:0
          collisions:0 txqueuelen:3000
          RX bytes:1060327667 (1011.2 MiB)  TX bytes:739208 (721.8 KiB)

ath1      Link encap:Ethernet  HWaddr 09:CD:7A:C9:11:29
          inet6 addr: fe80::bcd:7aff:fec9:1129/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1492  Metric:1
          RX packets:6715942 errors:0 dropped:6030763 overruns:0 frame:0
          TX packets:4076 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:3000
          RX bytes:1148797228 (1.0 GiB)  TX bytes:570178 (556.8 KiB)

can0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00
          UP RUNNING NOARP  MTU:16  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:10
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
          Interrupt:143

eth0      Link encap:Ethernet  HWaddr 52:B7:D6:55:8D:F2
          inet addr:10.0.0.229  Bcast:10.0.0.255  Mask:255.255.255.0
          inet6 addr: fe80::50b7:d6ff:fe55:8df2/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:202944 errors:0 dropped:0 overruns:0 frame:0
          TX packets:14990 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:23543957 (22.4 MiB)  TX bytes:6117126 (5.8 MiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:4172611 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4172611 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:577486664 (550.7 MiB)  TX bytes:577486664 (550.7 MiB)




   ******************************************************/
   '''
    command = cmd.split("obu")[1].strip()
    try:
        option = args[0]
    except IndexError:
        option = 0
        print("Please provide option")
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{} > ifconfig.txt".format(command))
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    obu_scp(child, "obu scp", "ifconfig.txt", dest_path)
    with open("{}/ifconfig.txt".format(dest_path), "r") as ifconfig:
        data = ifconfig.read()
    data_dict = {
        "HWaddr": re.search("HWaddr\s?((([\da-fA-F]){2}:?){6})", data),
        "inet addr": re.search("inet addr:\s?((\d{1,3}\.?){4})", data),
        "inet6 addr":
        re.search("inet6 addr:\s?([\da-fA-F:]+/64)", data),
        "RX packets": re.search(r"RX packets:(\d+)", data),
        "TX packets": re.search(r"TX packets:(\d+)", data),
        "RX dropped": re.search(r"RX.*dropped:(\d+)", data),
        "RX errors": re.search(r"RX.*errors:(\d+)", data),
        "TX dropped": re.search(r"TX.*dropped:(\d+)", data),
        "TX errors": re.search(r"TX.*errors:(\d+)", data),
    }
    print("option:", option)
    if not option:
        print("No option provided, displaying ifconfig output")
        print(data)
        return 0
    try:
        re_object = data_dict[option]
        value = re_object.group(1)
    except (KeyError, AttributeError):
        print("Please provide valid option or Pattern not found")
        return "-1"
    return int(value) if value.isnumeric() else value


def obu_tcpdump(child, cmd, interface, io, macaddr=None, msg=None, QOSData=None, sleep_val=7):
    '''
   /*****************************************************
    Function Name: obu_tcp_dump
    Description : This function is being used to check the transmisssion of the packets in the particular interface such as ath0, ath1 and eth0.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu tcpdump -i ath0 -POUT

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu tcpdump { -i ath0 -POUT} ?????????????????
    Output:
    root@US16SIQC:~# tcpdump -i ath0 -POUT
    tcpdump: WARNING: ath0: no IPv4 address assigned
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on ath0, link-type EN10MB (Ethernet), capture size 65535 bytes


   ******************************************************/
   '''
    global _HEXDUMP
    child.sendline("")
    child.expect(config.OBUPMT)
    if not macaddr:
        command = "tcpdump -i {0} -{1} -X".format(interface, io)
        child.sendline(command)
        sleep(3)
        child.sendcontrol("C")
        child.expect(config.OBUPMT)
        sleep(2)
        data = str(child.before, "utf-8")
        # print("TCPDUMP:{}".format(data))
        try:
            mac = re.search("(([\da-fA-F]){2}:?){6}", data).group()
            print("MAC:{}".format(mac))
            return mac
        except AttributeError:
            print("No dump found")
            return "-1"
    if QOSData == "True":
        command = "tcpdump -i {0} ether host {1} -{2} -XX > tcpdump.txt".format(
            interface, macaddr, io)
    else:
        command = "tcpdump -i {0} ether host {1} -{2} -X > tcpdump.txt".format(
            interface, macaddr, io)
    child.sendline(command)
    sleep(int(sleep_val))
    child.sendcontrol("C")
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    dest_path = "{}/resource/files".format(dest_path)
    obu_scp(child, "obu scp", "tcpdump.txt", dest_path)
    hexdump = None
    with open("{}/tcpdump.txt".format(dest_path)) as tcpdump:
        hexdump = tcpdump.read()
    hexdump = re.sub(r"\t", "", hexdump)
    try:
        info_ind = [ind.start() for ind in
                    re.finditer("\d\d:\d\d:\d\d\.\d", hexdump)]
        # works but need to write it clean
        hexdump = hexdump[info_ind[5]+50:info_ind[6]]
        _HEXDUMP = True
    except (IndexError, AttributeError):
        print("No hexdump found")
        _HEXDUMP = False
        return "-1"
    print("RAW_HEX_CODE:\n{}".format(hexdump))
    tcpdump = re.findall(r"\b[\da-fA-F]{4}\b[^:]", hexdump)

    def func(x, y): return x + y
    tcpdump = reduce(func, tcpdump)
    return tcpdump


def wsmp_head(child, command, *args, pick=None, msg=None):
    '''
   /*****************************************************
    Function Name: obu_wsmp_head
    Description : This function is being used decode the header information of the wsmp.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu wsmp head decode
    pick : If pick is none it will decode the latest hex value.
    msg : This option is used to filter the messages(bsm/tim/spat) in tcpdump output
          This option is used only with the command which is provided as example one.

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example :1) obu wsmp head decode {interface, macaddr, io, option}
             2) obu wsmp head decode {option, true}
   ******************************************************/
    '''
    global _HEXDUMP
    if len(args) > 2:
        interface = args[0]
        macaddr = args[1]
        io = args[2]
        option = args[3]
        if re.search("msg\s?=", args[-1]):
            # we should not use **kwargs to get the key value pairs. It will\
            # break some of the check status search patterns
            msg = re.split("=", args[-1])[1].strip()
        # When we are decoding new tcpdump we need to init the wsmp.
        wsmpHead.wsmp_head_init()
    elif len(args) <= 2:
        if not _HEXDUMP:
            print("No hexdump found. returning -1")
            return "-1"
        option = args[0]
        pick = args[1]
    if pick:
        with open("{}/resource/files/wsmphead.pickle".format(
                config.SAFE_FW_PATH), "rb") as data:
            wsmphead = pickle.load(data)
            option = option.strip()
            return wsmphead[option]
    hexdump = None
    if re.search(r"obu", command):
        hexdump = obu_tcpdump(child, command, interface, io, macaddr, msg)
        if hexdump == "-1":
            return "-1"
        print("\n")
        print("OBU_CLEAN_HEXCODE:\n{}".format(hexdump))
        if hexdump == "-1":
            return "-1"
    else:
        hexdump = tcp_dump(child, command, interface, macaddr, io, msg)
        print("\n")
        print("RSU_CLEAN_HEXCODE:\n{}".format(hexdump))
        if hexdump == "-1":
            return "-1"
    if hexdump:
        hexdump = re.sub(r"\s+", "", hexdump)
        llc_head = "88dc"
        llc_head_pos = re.search(llc_head, hexdump[:20])
        wsmp_dump = None
        if llc_head_pos:
            llc_head_pos_end = llc_head_pos.end()
            wsmp_dump = hexdump[llc_head_pos_end:]
        else:
            wsmp_dump = hexdump
        wsmp_dump = wsmpHead.wsmp_head_dec(wsmp_dump)
        wsmp_dump = wsmpHead.wsa_head_dec(
            wsmp_dump) if wsmpHead.T_head["PSID"] == 0x8007 else wsmpHead.lat_long_ele_conv()
        wsmp_dump = wsmpHead.wsm_security_trailer_dec(
            wsmp_dump) if wsmpHead.T_head["secured"] else print()
        wsmp_head_dict = {
            "wsmp subtype": wsmpHead.N_head["subtype"],
            "wsmp option ind": wsmpHead.N_head["opt_ind"],
            "wsmp version": wsmpHead.N_head["version"],
            "wsmp TPID": wsmpHead.N_head["TPID"],
            "wsmp count": wsmpHead.wave_info_elm_ext["count"],
            "wsmp PSID": wsmpHead.T_head["PSID"],
            "wsmp length before": wsmpHead.T_head["wsm_len_before"],
            "wsmp length after": wsmpHead.T_head["wsm_len_after"],
            "wsmp secured": wsmpHead.T_head["secured"],
            "wsmp unsecured": wsmpHead.T_head["unsecured"],
            "wsmp unsecured data": wsmpHead.wsm["unsecure_payload"],
            "wsa version": wsmpHead.wsa_head["version"],
            "wsa option ind": wsmpHead.wsa_head["opt_ind"],
            "wsa identifier": wsmpHead.wsa_head["wsa_id"],
            "wsa content count": wsmpHead.wsa_head["cntnt_cnt"],
            "wsa head info element extension count": wsmpHead.wsa_head["wsa_head_info_elm_ext"]["count"],
            "wsa service info segment count": wsmpHead.wsa_serv_info_seg["count"],
            "wsa channel info segment count": wsmpHead.wsa_ch_info_seg["count"],
            "Transmit Power Used elm id": wsmpHead.Info_elm_Dict_def["tx_pwr_used"]["elm_id"],
            "Transmit Power Used elm len": wsmpHead.Info_elm_Dict_def["tx_pwr_used"]["elm_len"],
            "Transmit Power Used elm val": wsmpHead.Info_elm_Dict_def["tx_pwr_used"]["elm_val"],
            "2D Location elm id": wsmpHead.Info_elm_Dict_def["2d_location"]["elm_id"],
            "2D Location elm len": wsmpHead.Info_elm_Dict_def["2d_location"]["elm_len"],
            "2D Location elm val": wsmpHead.Info_elm_Dict_def["2d_location"]["elm_val"],
            "3D Location elm id": wsmpHead.Info_elm_Dict_def["3d_location"]["elm_id"],
            "3D Location elm len": wsmpHead.Info_elm_Dict_def["3d_location"]["elm_len"],
            "3D Location elm val": wsmpHead.Info_elm_Dict_def["3d_location"]["elm_val"],
            "Advertiser Identifier elm id": wsmpHead.Info_elm_Dict_def["advt_idnt"]["elm_id"],
            "Advertiser Identifier elm len": wsmpHead.Info_elm_Dict_def["advt_idnt"]["elm_len"],
            "Advertiser Identifier elm val": wsmpHead.Info_elm_Dict_def["advt_idnt"]["elm_val"],
            "Provider Service Context elm id":
            wsmpHead.Info_elm_Dict_def["prv_serv_cntxt"]["elm_id"],
            "Provider Service Context elm len":
            wsmpHead.Info_elm_Dict_def["prv_serv_cntxt"]["elm_len"],
            "Provider Service Context elm val":
            wsmpHead.Info_elm_Dict_def["prv_serv_cntxt"]["elm_val"],
            "IPv6 Address elm id": wsmpHead.Info_elm_Dict_def["ipv6_addr"]["elm_id"],
            "IPv6 Address elm len": wsmpHead.Info_elm_Dict_def["ipv6_addr"]["elm_len"],
            "IPv6 Address elm val": wsmpHead.Info_elm_Dict_def["ipv6_addr"]["elm_val"],
            "Service Port elm id": wsmpHead.Info_elm_Dict_def["serv_port"]["elm_id"],
            "Service Port elm len": wsmpHead.Info_elm_Dict_def["serv_port"]["elm_len"],
            "Service Port elm val": wsmpHead.Info_elm_Dict_def["serv_port"]["elm_val"],
            "Provider MAC Address elm id": wsmpHead.Info_elm_Dict_def["prv_mac_addr"]["elm_id"],
            "Provider MAC Address elm len":
            wsmpHead.Info_elm_Dict_def["prv_mac_addr"]["elm_len"],
            "Provider MAC Address elm val":
            wsmpHead.Info_elm_Dict_def["prv_mac_addr"]["elm_val"],
            "EDCA Parameter Set elm id": wsmpHead.Info_elm_Dict_def["edca_par_set"]["elm_id"],
            "EDCA Parameter Set elm len": wsmpHead.Info_elm_Dict_def["edca_par_set"]["elm_len"],
            "EDCA Parameter Set elm val": wsmpHead.Info_elm_Dict_def["edca_par_set"]["elm_val"],
            "Secondary DNS elm id": wsmpHead.Info_elm_Dict_def["sec_dns"]["elm_id"],
            "Secondary DNS elm len": wsmpHead.Info_elm_Dict_def["sec_dns"]["elm_len"],
            "Secondary DNS elm val": wsmpHead.Info_elm_Dict_def["sec_dns"]["elm_val"],
            "Gateway MAC Address elm id": wsmpHead.Info_elm_Dict_def["gw_mac_addr"]["elm_id"],
            "Gateway MAC Address elm len": wsmpHead.Info_elm_Dict_def["gw_mac_addr"]["elm_len"],
            "Gateway MAC Address elm val": wsmpHead.Info_elm_Dict_def["gw_mac_addr"]["elm_val"],
            "Channel Number elm id": wsmpHead.Info_elm_Dict_def["ch_num"]["elm_id"],
            "Channel Number elm len": wsmpHead.Info_elm_Dict_def["ch_num"]["elm_len"],
            "Channel Number elm val": wsmpHead.Info_elm_Dict_def["ch_num"]["elm_val"],
            "Data Rate elm id": wsmpHead.Info_elm_Dict_def["data_rate"]["elm_id"],
            "Data Rate elm len": wsmpHead.Info_elm_Dict_def["data_rate"]["elm_len"],
            "Data Rate elm val": wsmpHead.Info_elm_Dict_def["data_rate"]["elm_val"],
            "Repeat Rate elm id": wsmpHead.Info_elm_Dict_def["repeat_rate"]["elm_id"],
            "Repeat Rate elm len": wsmpHead.Info_elm_Dict_def["repeat_rate"]["elm_len"],
            "Repeat Rate elm val": wsmpHead.Info_elm_Dict_def["repeat_rate"]["elm_val"],
            "RCPI Threshold elm id": wsmpHead.Info_elm_Dict_def["rcpi_threshhold"]["elm_id"],
            "RCPI Threshold elm len": wsmpHead.Info_elm_Dict_def["rcpi_threshhold"]["elm_len"],
            "RCPI Threshold elm val": wsmpHead.Info_elm_Dict_def["rcpi_threshhold"]["elm_val"],
            "WSA Count Threshold elm id":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold"]["elm_id"],
            "WSA Count Threshold elm len":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold"]["elm_len"],
            "WSA Count Threshold elm val":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold"]["elm_val"],
            "Channel Access elm id": wsmpHead.Info_elm_Dict_def["ch_access"]["elm_id"],
            "Channel Access elm len": wsmpHead.Info_elm_Dict_def["ch_access"]["elm_len"],
            "Channel Access elm val":
            wsmpHead.Info_elm_Dict_def["ch_access"]["elm_val"],
            "WSA Count Threshold Interval elm id":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold_intrvl"]["elm_id"],
            "WSA Count Threshold Interval elm len":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold_intrvl"]["elm_len"],
            "WSA Count Threshold Interval elm val":
            wsmpHead.Info_elm_Dict_def["wsa_cnt_threshhold_intrvl"]["elm_val"],
            "Channel Load elm id": wsmpHead.Info_elm_Dict_def["ch_load"]["elm_id"],
            "Channel Load elm len": wsmpHead.Info_elm_Dict_def["ch_load"]["elm_len"],
            "Channel Load elm val": wsmpHead.Info_elm_Dict_def["ch_load"]["elm_val"],
            "location latitude": wsmpHead.wsa_head_info_elm_ext["info_elm"]["lat"],
            "location longitude": wsmpHead.wsa_head_info_elm_ext["info_elm"]["lon"],
            "location elevation": wsmpHead.wsa_head_info_elm_ext["info_elm"]["elv"],
            "service info instance 23":
            wsmpHead.serv_info_inst_get(0x23, "PSID"),
            "service info instance chan index 23":
            wsmpHead.serv_info_inst_get(0x23, "ch_ind"),
            "service info instance reserved 23":
            wsmpHead.serv_info_inst_get(0x23, "reserved"),
            "service info instance opt ind 23":
            wsmpHead.serv_info_inst_get(0x23, "opt_in"),

            "service info instance 8004":
                wsmpHead.serv_info_inst_get(0x8004, "PSID"),
            "service info instance chan index 8004":
                wsmpHead.serv_info_inst_get(0x8004, "ch_ind"),
            "service info instance reserved 8004":
                wsmpHead.serv_info_inst_get(0x8004, "reserved"),
            "service info instance opt ind 8004":
                wsmpHead.serv_info_inst_get(0x8004, "opt_in"),

            "service info instance EFFFFFFE":
                wsmpHead.serv_info_inst_get(0xEFFFFFFE, "PSID"),
            "service info instance chan index EFFFFFFE":
                wsmpHead.serv_info_inst_get(0xEFFFFFFE, "ch_ind"),
            "service info instance reserved EFFFFFFE":
                wsmpHead.serv_info_inst_get(0xEFFFFFFE, "reserved"),
            "service info instance opt ind EFFFFFFE":
                wsmpHead.serv_info_inst_get(0xEFFFFFFE, "opt_in"),

            "service info instance 7f":
            wsmpHead.serv_info_inst_get(0x7F, "PSID"),
            "service info instance chan index 7F":
            wsmpHead.serv_info_inst_get(0x7F, "ch_ind"),
            "service info instance reserved 7F":
            wsmpHead.serv_info_inst_get(0x7F, "reserved"),
            "service info instance opt ind 7F":
            wsmpHead.serv_info_inst_get(0x7F, "opt_in"),
            "service info instance 7E":
            wsmpHead.serv_info_inst_get(0x7E, "PSID"),
            "service info instance chan index 7E":
            wsmpHead.serv_info_inst_get(0x7E, "ch_ind"),
            "service info instance reserved 7E":
            wsmpHead.serv_info_inst_get(0x7E, "reserved"),
            "service info instance opt ind 7E":
            wsmpHead.serv_info_inst_get(0x7E, "opt_in"),

            "service info instance info element count":
            wsmpHead.sis_wave_info_elm_ext["count"],

            "channel info instance count 7f":
            wsmpHead.ch_info_inst_get(0x7f, "count"),
            "channel info instance operating class 7f":
            wsmpHead.ch_info_inst_get(0x7f, "operating_class"),
            "channel info instance channel number 7f":
            wsmpHead.ch_info_inst_get(0x7f, "ch_num"),
            "channel info instance transmit power level 7f":
            wsmpHead.ch_info_inst_get(0x7f, "tx_pwr_level"),
            "channel info instance adaptble 7f":
            wsmpHead.ch_info_inst_get(0x7f, "adaptable"),
            "channel info instance datarate 7f":
            wsmpHead.ch_info_inst_get(0x7f, "data_rate"),

            "channel info instance of channel access id 7f":
            wsmpHead.ch_info_inst_get(0x7f, "ch_access", "elm_id"),
            "channel info instance of channel access len 7f":
            wsmpHead.ch_info_inst_get(0x7f, "ch_access", "elm_len"),
            "channel info instance of channel access val 7f":
            wsmpHead.ch_info_inst_get(0x7f, "ch_access", "elm_val"),

            "service info instance 8000":
            wsmpHead.serv_info_inst_get(0x8000, "PSID"),
            "service info instance chan index 8000":
            wsmpHead.serv_info_inst_get(0x8000, "ch_ind"),
            "service info instance reserved 8000":
            wsmpHead.serv_info_inst_get(0x8000, "reserved"),
            "service info instance opt ind 8000":
            wsmpHead.serv_info_inst_get(0x8000, "opt_in"),
            "service info instance 8002":
            wsmpHead.serv_info_inst_get(0x8002, "PSID"),
            "service info instance chan index 8002":
            wsmpHead.serv_info_inst_get(0x8002, "ch_ind"),
            "service info instance reserved 8002":
            wsmpHead.serv_info_inst_get(0x8002, "reserved"),
            "service info instance opt ind 8002":
            wsmpHead.serv_info_inst_get(0x8002, "opt_in"),
            "service info instance 8003":
            wsmpHead.serv_info_inst_get(0x8003, "PSID"),
            "service info instance chan index 8003":
            wsmpHead.serv_info_inst_get(0x8003, "ch_ind"),
            "service info instance reserved 8003":
            wsmpHead.serv_info_inst_get(0x8003, "reserved"),
            "service info instance opt ind 8003":
            wsmpHead.serv_info_inst_get(0x8003, "opt_in"),
            "channel info instance count 23":
            wsmpHead.ch_info_inst_get(0x23, "count"),
            "channel info instance operating class 23":
            wsmpHead.ch_info_inst_get(0x23, "operating_class"),
            "channel info instance channel number 23":
            wsmpHead.ch_info_inst_get(0x23, "ch_num"),
            "channel info instance transmit power level 23":
            wsmpHead.ch_info_inst_get(0x23, "tx_pwr_level"),
            "channel info instance adaptble 23":
            wsmpHead.ch_info_inst_get(0x23, "adaptable"),
            "channel info instance datarate 23":
            wsmpHead.ch_info_inst_get(0x23, "data_rate"),
            "channel info instance count 8004":
            wsmpHead.ch_info_inst_get(0x8004, "count"),
            "channel info instance operating class 8004":
            wsmpHead.ch_info_inst_get(0x8004, "operating_class"),
            "channel info instance channel number 8004":
            wsmpHead.ch_info_inst_get(0x8004, "ch_num"),
            "channel info instance transmit power level 8004":
            wsmpHead.ch_info_inst_get(0x8004, "tx_pwr_level"),
            "channel info instance adaptble 8004":
            wsmpHead.ch_info_inst_get(0x8004, "adaptable"),
            "channel info instance datarate 8004":
            wsmpHead.ch_info_inst_get(0x8004, "data_rate"),
            "channel info instance count EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "count"),
            "channel info instance operating class EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "operating_class"),
            "channel info instance channel number EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "ch_num"),
            "channel info instance transmit power level EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "tx_pwr_level"),
            "channel info instance adaptble EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "adaptable"),
            "channel info instance datarate EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "data_rate"),
            "channel info instance count 8000":
            wsmpHead.ch_info_inst_get(0x8000, "count"),
            "channel info instance operating class 8000":
            wsmpHead.ch_info_inst_get(0x8000, "operating_class"),
            "channel info instance channel number 8000":
            wsmpHead.ch_info_inst_get(0x8000, "ch_num"),
            "channel info instance transmit power level 8000":
            wsmpHead.ch_info_inst_get(0x8000, "tx_pwr_level"),
            "channel info instance adaptble 8000":
            wsmpHead.ch_info_inst_get(0x8000, "adaptable"),
            "channel info instance datarate 8000":
            wsmpHead.ch_info_inst_get(0x8000, "data_rate"),
            "channel info instance count 8002":
            wsmpHead.ch_info_inst_get(0x8002, "count"),
            "channel info instance operating class 8002":
            wsmpHead.ch_info_inst_get(0x8002, "operating_class"),
            "channel info instance channel number 8002":
            wsmpHead.ch_info_inst_get(0x8002, "ch_num"),
            "channel info instance transmit power level 8002":
            wsmpHead.ch_info_inst_get(0x8002, "tx_pwr_level"),
            "channel info instance adaptble 8002":
            wsmpHead.ch_info_inst_get(0x8002, "adaptable"),
            "channel info instance datarate 8002":
            wsmpHead.ch_info_inst_get(0x8002, "data_rate"),
            "channel info instance count 8003":
            wsmpHead.ch_info_inst_get(0x8003, "count"),
            "channel info instance operating class 8003":
            wsmpHead.ch_info_inst_get(0x8003, "operating_class"),
            "channel info instance channel number 8003":
            wsmpHead.ch_info_inst_get(0x8003, "ch_num"),
            "channel info instance transmit power level 8003":
            wsmpHead.ch_info_inst_get(0x8003, "tx_pwr_level"),
            "channel info instance adaptble 8003":
            wsmpHead.ch_info_inst_get(0x8003, "adaptable"),
            "channel info instance datarate 8003":
            wsmpHead.ch_info_inst_get(0x8003, "data_rate"),
            "routing advrt router lifetime":
            wsmpHead.wsa_routing_advt["router_lifetime"],
            "routing advrt ip prefix":
            wsmpHead.wsa_routing_advt["ip_prefix"],
            "routing advrt prefix length":
            wsmpHead.wsa_routing_advt["prefix_len"],
            "routing advrt default gateway":
            wsmpHead.wsa_routing_advt["default_gateway"],
            "routing advrt primary dns":
            wsmpHead.wsa_routing_advt["primary_dns"],
            "route wave info elm ext count":
            wsmpHead.wsa_routing_advt["rout_wave_info_elm_ext"]["count"],
            "channel info instance of channel access id EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "ch_access", "elm_id"),
            "channel info instance of channel access len EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "ch_access", "elm_len"),
            "channel info instance of channel access val EFFFFFFE":
            wsmpHead.ch_info_inst_get(0xEFFFFFFE, "ch_access", "elm_val"),
            "channel info instance of channel access id 8003":
            wsmpHead.ch_info_inst_get(0x8003, "ch_access", "elm_id"),
            "channel info instance of channel access len 8003":
            wsmpHead.ch_info_inst_get(0x8003, "ch_access", "elm_len"),
            "channel info instance of channel access val 8003":
            wsmpHead.ch_info_inst_get(0x8003, "ch_access", "elm_val"),
            "security header protocol version": wsmpHead.security_hdr["protocol_version"],
            "security header choice tag": wsmpHead.security_hdr["choice tag"],
            "security header content": wsmpHead.security_hdr["content"],
            "security header hashID": wsmpHead.security_hdr["signed_data"]["hashID"],
            "tbS data extension bit": wsmpHead.tbs_data["extension_bit"],
            "tbS data optional field bit for data": wsmpHead.tbs_data["optional field bit for data"],
            "tbS data optional field bit for extdHash": wsmpHead.tbs_data["optional field bit for extdHash"],
            "secure header data protocol version": wsmpHead.secure_hdr_data["protocol_version"],
            "secure header data choice tag": wsmpHead.secure_hdr_data["choice tag"],
            "security header content payload length": wsmpHead.security_hdr_content["payload_length"],
            "security header unsecured_data": wsmpHead.security_hdr_content["unsecured_data"],

            "security trailer header extension bit": wsmpHead.security_trailer_header_info["Extension_bit"],
            "security trailer header generation time present": wsmpHead.security_trailer_header_info["generation_time_present"],
            "security trailer header Expiry_time is present": wsmpHead.security_trailer_header_info["Expiry_time_is_present"],
            "security trailer header generation location present": wsmpHead.security_trailer_header_info["generation_location_present"],
            "security trailer header p2pcd learning request": wsmpHead.security_trailer_header_info["p2pcd_learning_request"],
            "security trailer header missing crl identifier": wsmpHead.security_trailer_header_info["missing_crl_identifier"],
            "security trailer header encryption key": wsmpHead.security_trailer_header_info["encryption_key"],
            "security trailer header integer length": wsmpHead.security_trailer_header_info["integer_length"],
            "security trailer header psid": wsmpHead.security_trailer_header_info["psid"],
            "security trailer header generation time": wsmpHead.security_trailer_header_info["generation_time"],
            "security trailer header expiry_time": wsmpHead.security_trailer_header_info["expiry_time"],
            "security trailer header generation location latitude": wsmpHead.security_trailer_header_info["generation_location"]["lat"],
            "security trailer header generation location longitude": wsmpHead.security_trailer_header_info["generation_location"]["lon"],
            "security trailer header generation location elevation": wsmpHead.security_trailer_header_info["generation_location"]["elv"],
            "security trailer header choice tag": wsmpHead.security_trailer_header_info["choice_tag"],
            "security signer": wsmpHead.signer_info["signer"],
            "signer sequence of length": wsmpHead.signer_info["sequence_of_length"],

            "certificate info signature is not present": wsmpHead.certificate_info["signature_is_not_present"],
            "certificate info version": wsmpHead.certificate_info["version"],
            "certificate info Extension present bit": wsmpHead.certificate_info["Extension_present_bit"],
            "certificate info signature choice tag": wsmpHead.certificate_info["choice tag"],
            "certificate info signature sha256 and digest": wsmpHead.certificate_info["sha256_and_digest"],



            "signed Extension bit": wsmpHead.to_be_signed["Extension_bit"],
            "signed region": wsmpHead.to_be_signed["region"],
            "signed assurance level": wsmpHead.to_be_signed["assurance_level"],
            "signed app permissionOf": wsmpHead.to_be_signed["app_permissionOf"],
            "signed certIssuePermissions": wsmpHead.to_be_signed["certIssuePermissions"],
            "signed certRequestpermissions": wsmpHead.to_be_signed["certRequestpermissions"],
            "signed canRequestRollover": wsmpHead.to_be_signed["canRequestRollover"],
            "signed encryption_key": wsmpHead.to_be_signed["encryption_key"],
            "signed choice_tag": wsmpHead.to_be_signed["choice_tag"],
            "signed linkage data": wsmpHead.to_be_signed["linkage_data"],
            "signed iCert": wsmpHead.to_be_signed["iCert"],
            "signed linkage value": wsmpHead.to_be_signed["linkage_value"],
            "signed cracaid": wsmpHead.to_be_signed["cracaid"],
            "signed crlSeries": wsmpHead.to_be_signed["crlSeries"],
            "signed Validity period start": wsmpHead.to_be_signed["Validity_period_start"],
            "signed Validity period duration": wsmpHead.to_be_signed["Validity_period_duration"],
            "signed Validity period assurance level": wsmpHead.to_be_signed["Validity_period_assurance_level"],
            "signed sequence of length": wsmpHead.to_be_signed["sequence_of_length"],
            "signed app permissions ssp present": wsmpHead.to_be_signed["app_permissions_ssp_present"],
            "signed integer length": wsmpHead.to_be_signed["integer length"],
            "signed PSID": wsmpHead.to_be_signed["PSID"],
            "signed app_permissions choice tag": wsmpHead.to_be_signed["app_permissions_choice_tag"],
            "signed ssp len": wsmpHead.to_be_signed["ssp_len"],
            "signed app pemissionsOf choice tag": wsmpHead.to_be_signed["app_pemissionsOf_choice_tag"],

            "verify key indicator choice tag": wsmpHead.verify_key_indicator["choice_tag"],
            "verify key indicator compressed_y_1": wsmpHead.verify_key_indicator["compressed_y_1"],
            "security signature": wsmpHead.signature["signature"],
            "signature choice tag": wsmpHead.signature["choice_tag"],
            "signature r": wsmpHead.signature["r"],
            "signature Compressed_y_1": wsmpHead.signature["Compressed_y_1"],
            "signature S": wsmpHead.signature["s"]
        }
        with open("{}/resource/files/wsmphead.pickle".format(
                config.SAFE_FW_PATH), "wb") as data:
            pickle.dump(wsmp_head_dict, data, pickle.HIGHEST_PROTOCOL)
        if option:
            option = option.strip()
            print("OPTION:{}".format(option))
            value = wsmp_head_dict[option]
            return value
        else:
            print("Option didn't provide")
            print(json.dumps(wsmp_head_dict, indent=4))
            return "-1"


def euobu_hexdump_get():
    '''
   /*****************************************************
    Function Name: euobu_hexdump_get
    Description : This function is being used to get the hex dump from the tcpdump.
                  (refer api_wrapper.txt for associated commands with the API)

     Return Value : tcpdump
                   Data type: String

    Type : External API




   ******************************************************/
   '''
    with open("{}/resource/files/eutcpdump.txt".format(config.SAFE_FW_PATH)) as tcpfile:
        tcpcode = tcpfile.read()
        tcpcode = re.sub(r"\t", "", tcpcode)
        try:
            tcpcode = tcpcode + tcpcode
            info_ind = [ind.start() for ind in
                        re.finditer("\d\d:\d\d:\d\d\.\d", tcpcode)]
            tcpcode = tcpcode[info_ind[0]:info_ind[1]]
            _HEXDUMP = True
        except (IndexError, AttributeError):
            print("No hexdump found")
            _HEXDUMP = False
            return "-1"
        print("RAW_HEX_CODE:\n{}".format(tcpcode))
        tcpdump = re.findall(r"\b[\da-fA-F]{4}\b", tcpcode)

        def func(x, y): return x + y
        tcpdump = reduce(func, tcpdump)
        return tcpdump


def etsi_head(child, command, *args, pick=None, msg=None):
    '''
   /*****************************************************
    Function Name: etsi_head
    Description : This function is being used decode the information of the etsi packet.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu wsmp head decode
    pick : If pick is none it will decode the latest hex value.
    msg : hex code value

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu gn header decode {ath1, @mac, out, bh version}


   ******************************************************/
   '''
    global _HEXDUMP
    if len(args) > 2:
        interface = args[0]
        macaddr = args[1]
        io = args[2]
        try:
            option = args[3]
        except IndexError:
            option = None
        if re.search("msg\s?=", args[-1]):
            # we should not use **kwargs to get the key value pairs. It will\
            # break some of the check status search patterns
            msg = re.split("=", args[-1])[1].strip()
        # When we are decoding new tcpdump we need to init the wsmp.
        # print(dir(etsihead))
        etsihead.gn_hdr_init()
    elif len(args) <= 2:
        if not _HEXDUMP:
            print("No hexdump found. returning -1")
            return "-1"
        option = args[0]
        pick = args[1]
    if pick:
        with open("{}/resource/files/etsihead.pickle".format(
                config.SAFE_FW_PATH), "rb") as data:
            etsipkt = pickle.load(data)
            option = option.strip()
            return etsipkt[option]
    hexdump = None
    if re.search(r"obu", command, re.I):
        hexdump = euobu_hexdump_get()
        if hexdump == "-1":
            return "-1"
        print("\n")
        print("EUOBU_CLEAN_HEXCODE:\n{}".format(hexdump))
        if hexdump == "-1":
            return "-1"
    else:
        hexdump = euobu_tcpdump(child, command, interface, macaddr, io, msg)
        print("\n")
        print("EURSU_CLEAN_HEXCODE:\n{}".format(hexdump))
        if hexdump == "-1":
            return "-1"
    if hexdump:
        print("MSG:{}".format(msg))
        hexdump = re.sub(r"\s+", "", hexdump)
        llc_head = "8947"
        llc_head_pos = re.search(llc_head, hexdump)
        etsi_dump = None
        if llc_head_pos:
            llc_head_pos_end = llc_head_pos.end()
            etsi_dump = hexdump[llc_head_pos_end:]
            if option == "ether_type":
                return llc_head
        else:
            etsi_dump = hexdump
        etsi_dump = etsihead.gn_hdr_dec(etsi_dump)
        etsi_dump = etsihead.redirecting_api(etsi_dump)
        etsi_dump = etsihead.btp_hdr_dec(etsi_dump)
        try:
            exec_Flag = 1
            etsi_gnhdr_dict = {
                "bh version": etsihead.basic_hdr["version"],
                "bh NH": etsihead.basic_hdr["basic_next_header"],
                "bh reserved": etsihead.basic_hdr["basic_reserved"],
                "bh multiplier": etsihead.basic_hdr["lifetime"]["multiplier"],
                "bh base": etsihead.basic_hdr["lifetime"]["base"],
                "bh RHL": etsihead.basic_hdr["RHL"],
                "ch NH": etsihead.common_hdr["common_next_header"],
                "ch reserved1": etsihead.common_hdr["common_reserved1"],
                "ch HT": etsihead.common_hdr["header_type"],
                "ch HST": etsihead.common_hdr["header_sub_type"],
                "ch scf": etsihead.common_hdr["traffic_class"]["scf"],
                "ch channel offload": etsihead.common_hdr["traffic_class"]["channel_offload"],
                "ch tc id": etsihead.common_hdr["traffic_class"]["tc_id"],
                "ch gnsismobile": etsihead.common_hdr["flags"]["gnsismobile"],
                "ch flags reserved": etsihead.common_hdr["flags"]["flags_reserved"],
                "ch payload length": etsihead.common_hdr["payload_length"],
                "ch MHL": etsihead.common_hdr["max_hoplimit"],
                "ch reserved2": etsihead.common_hdr["common_reserved2"],
                "gn addr m": etsihead.lpv["so_gn_addr"]["manual_addr_conf"],
                "gn addr st": etsihead.lpv["so_gn_addr"]["station_type"],
                "gn addr scc": etsihead.lpv["so_gn_addr"]["station_country_code"],
                "gn addr mid": etsihead.lpv["so_gn_addr"]["MID"],
                "so pv tst": etsihead.lpv["so_tst"],
                "so pv lat": etsihead.lpv["so_lat"],
                "so pv long": etsihead.lpv["so_long"],
                "so pv pai": etsihead.lpv["pai"],
                "so pv speed": etsihead.lpv["speed"],
                "so pv heading": etsihead.lpv["heading"],
                "tsb pkt SN": etsihead.tsb_pkt_hdr["sequence_number"],
                "tsb pkt reserved": etsihead.tsb_pkt_hdr["tsb_reserved"],
                "shb pkt reserved": etsihead.shb_pkt_hdr["shb_reserved"],
                "gbc pkt SN": etsihead.gbc_pkt_hdr["sequence_number"],
                "gbc pkt reserved1": etsihead.gbc_pkt_hdr["gbc_reserved1"],
                "gbc pkt GeoAreaPos lat": etsihead.gbc_pkt_hdr["geo_area_pos_lat"],
                "gbc pkt GeoAreaPos long": etsihead.gbc_pkt_hdr["geo_area_pos_long"],
                "gbc pkt dist a": etsihead.gbc_pkt_hdr["dist_a"],
                "gbc pkt dist b": etsihead.gbc_pkt_hdr["dist_b"],
                "gbc pkt angle": etsihead.gbc_pkt_hdr["angle"],
                "gbc pkt reserved2": etsihead.gbc_pkt_hdr["gbc_reserved2"],
                "btp pkt destPort": etsihead.btp_hdr["dest_port"],
                "btp pkt destPort Info": etsihead.btp_hdr["dest_port_info"]

            }
            with open("{}/resource/files/etsihead.pickle".format(
                    config.SAFE_FW_PATH), "wb") as data:
                pickle.dump(etsi_gnhdr_dict, data, pickle.HIGHEST_PROTOCOL)
        except Exception:
            print("Issue with ETSI decoder or hexdump. Verify both")
            return None
        if option:
            option = option.strip()
            print("OPTION:{}".format(option))
            value = etsi_gnhdr_dict[option]
            return value
        else:
            print("Option didn't provide")
            print(json.dumps(etsihead.gn_hdr, indent=4))
            return exec_Flag


def snmp_func(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_snmp_func
    Description : This function is being used know the information of the snmp and set the snmp.
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  snmpset OR snmpget

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example :snmpset OR snmpget


   ******************************************************/
   '''
    ver = args[0]
    uname = args[1]
    chksum = args[2]
    pwd = args[3]
    authen = args[4]
    ip = args[5]
    OID = args[6]
    try:
        string = args[7]
        get_output = sp.run(["{0} -v {1} -u {2} -a  {3} -A {4} -l \
{5} {6} {7} s {8}\r".format(cmd, ver, uname, chksum, pwd, authen,
                            ip, OID, string)], stdout=sp.PIPE, shell=True)
        (data, err) = get_output.communicate()
        snmp_data = str(data)
        return data
    except IndexError:
        get_output = sp.run(["{0} -v {1} -u {2} -a  {3} -A {4} -l \
{5} {6} {7}\r".format(cmd, ver, uname, chksum, pwd, authen,
                      ip, OID)], stdout=sp.PIPE, shell=True)
        (data, err) = get_output.communicate()
        snmp_data = str(data)
        return data
        pass


def euobu_run_command_show(child, command):
    '''
   /*****************************************************
    Function Name: euobu_run_command_show
    Description : This function is being used show the command output.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : Function

    Example : not using in the text file.


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    try:
        sleep(3)
        child.sendcontrol("C")
        child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
        # child.expect(config.OBUPMT)
        print("run_command_show:", command)
        child.sendline("{0}\r".format(command))
        sleep(2)
        # child.expect(config.OBUPMT)
        child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
        data_return = child.before
        data_return = re.sub(r"\r", "", data_return.decode('utf-8'))
        data_return = re.sub(r"(\n)+", "\n", data_return)
        return data_return
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        child.kill(0)
        child.terminate(force=True)
        child.close(force=True)
        return 0


def euobu_file_read(child, cmd, *args, occurance=None):
    '''
   /*****************************************************
    Function Name: euobu_file_read
    Description : This function is being used read the input parameter from the config file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  obu read file {@output, file name,input string}

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu read file {@output, file name,input string}


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    command = "awk '/%s/{print}' %s" % (args[1], args[0])
    data = euobu_run_command_show(child, command)
    if data is None:
        print("Received None and returning None...")
        return None
    data_list = data.split("\n")
    print(data)
    if occurance:
        compile_text = args[1]
        return len(re.findall(r"{}(\s+)?=".format(compile_text), data))
    stringValue = ''
    for line in data_list:
        if args[1] in line and '=' in line:
            stringValue = line.split()
            break
        else:
            pass
    try:
        stringValue = stringValue[2]
        stringValue = stringValue.split(';')
    except KeyError:
        print("KeyError : %s is not present in output" % (args[1]))

    return stringValue[0]


def euobu_gntool_getLocte(child, command, *args):
    '''
   /*****************************************************
    Function Name: euobu_gntool_getLocte
    Description : This function is being used to check the GN(Geo networking) location table.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu gntool get_locte(check the data in GN loaction table) .

    Return Value : String data(Result of the command or Failure reason).
    Type : External API
    Example : obu gntool get_locte


   ******************************************************/
    '''
    """ Author: Nilesh Guhe
    """

    command = command.split("obu")[1].strip()
    data = euobu_run_command_show(child, command)
    if data is None:
        print("Received None and returning None...")
        return None
    print(data)
    data = re.sub(r"\t", "", data)
    data1 = data.split('\n')
    data2 = data1[1].split()
    data2 = int(data2[2])
    if data2 == 1:
        print("Number of device entry is found 1")
    elif data2 == 0:
        print("Number of device entry is found 0")
        data = 'N Entries: 0'
        return data
    elif data2 > 1:
        print("Number of device entry is found more than 1")
    dictOut = {}
    try:
        if data2 == 1:
            dataN = data1
            indexNo = data1.index('Position Vector')
            data1 = data1[3:indexNo]
            lastValue = data1.pop()
            lastValue = lastValue.replace('|', '')
            lastValue = lastValue.replace(' : ', ' ')
            data1.pop()
            data1.pop()
            lastValue = lastValue.split()
            for i in data1:
                i = i.split()
                dictValue = {i[0]: i[1]}
                dictValueOut = dictOut.update(dictValue)

            dictValue = {lastValue[0]: lastValue[1]}
            dictOut.update(dictValue)
            dictValue = {lastValue[2]: lastValue[3]}
            dictOut.update(dictValue)
            dictValue = {lastValue[4]: lastValue[5]}
            dictOut.update(dictValue)
            dictValue = {lastValue[6]: lastValue[7]}
            dictOut.update(dictValue)

            for i in range(6):
                i = i + 3
                output = dataN[indexNo + i]
                output = output.split()
                dictValue = {output[0]: output[1]}
                dictOut.update(dictValue)
            dictOut = dictOut[args[0]]

        return dictOut
    except KeyError:
        print("Please check the received output")


def sys_login(child, cmd, SYS_UNAME, SYS_HOST, SYS_PWD):
    '''
   /*****************************************************
    Function Name: sys_login
    Description : This function is being used login to the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : sys login
    SYS_UNAME: It is the user name of the system.
    SYS_HOST: It is the ip address of the system.
    SYS_PWD: It is the password of the System.
     Return Value : Result of the command or Failure reason.
                   Data type: String
    Type : External API
    Example : sys login


   ******************************************************/
    '''
    ssh_login = "ssh -q -o UserKnownHostsFile=/dev/null -o \
        StrictHostKeyChecking=no {0}@{1}".format(SYS_UNAME, SYS_HOST)
    print("SSH_LOGIN:{}".format(ssh_login))
    system = pexpect.spawn(ssh_login)
    try:
        system.expect("password:")
        system.sendline(SYS_PWD)
    except pexpect.TIMEOUT:
        system.expect("connecting")
        system.sendline("y\r")
        system.expect("password:")
        system.sendline(SYS_PWD)
    print("Connected to {}".format(SYS_HOST))
    return system


def ggaclient(child, cmd, device, port, *args):
    dev_lgn_dtils = config.RSU_Dict[device]
    ip_addr = dev_lgn_dtils["HOSTIP"]
    command = "./{0} {1} -p {2}".format(cmd, ip_addr, port)
    print("Command:{}".format(command))
    system = sys_login(child, cmd, config.SYS_UNAME,
                       config.SYS_HOST, config.SYS_PASSWORD)
    system.sendline(command)
    sleep(5)
    system.sendcontrol("C")
    system.expect("robot.*$")
    sleep(5)
    data = str(system.before, "utf-8")
    system.close()
    return data


def euobu_tcpdump(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: euobu_tcpdump
    Description : This function is being used to check the packet transmission/reciption in the particular interface(ath0,ath1 and eth0).
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  euobu tcpdump -i POUT
     Return Value : Result of the command or Failure reason.
                   Data type: String
    Type : External API
    Example : euobu tcpdump -i POUT


   ******************************************************/
  '''
    """ Author: Nilesh Guhe
    """

    child.sendline("")
    child.expect(config.OBUPMT)
    if len(args) > 2:
        command = "tcpdump -i {0} -P {1} -XX ether host {2} > eutcpdump.txt".format(
            args[0], args[1], args[2])
    else:
        command = "tcpdump -i {0} -P {1} -XX > eutcpdump.txt".format(
            args[0], args[1])

    print(command)
    child.sendline(command)
    sleep(7)
    child.sendcontrol("C")
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    dest_path = "{}/resource/files".format(dest_path)
    command = "scp {} {}@{}:{}".format("eutcpdump.txt", config.SYS_UNAME,
                                       config.SYS_HOST, dest_path)
    obu_scp(child, "obu scp", "eutcpdump.txt", dest_path)
    sleep(2)
    file_path = "{}/eutcpdump.txt".format(dest_path)
    tcp_dump_backup(file_path)
    with open(file_path) as tcpdump:
        hexfile = tcpdump.read()
    print(hexfile)
    try:
        hexfile = re.sub(r"\t", "", hexfile)
        mac_addr = re.search(r"src:([\da-fA-F:]+)\s?", hexfile)
        mac_addr = mac_addr.group(1)
    except AttributeError:
        print("No tcpdump data found")
        return "-1"

    return mac_addr


def euobu_restart_process(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: euobu_restart_process
    Description : This function is being used restart/start/stop process in the system.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  euobu process {filename, restart/start/stop}
     Return Value : Result of the command or Failure reason.
                   Data type: String
    Type : External API
    Example : euobu process {filename, restart/start/stop}


   ******************************************************/
    '''
    """ Author: Nilesh Guhe
    """

    command = "{0} {1}".format(args[0], args[1])
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline(command)
    child.expect(config.OBUPMT)
    sleep(7)
    child.sendline("")
    printData = ""
    try:
        child.expect(config.OBUPMT, timeout=10)
        data = child.before
        printData = str(data, "utf-8")
        print(printData)
    except:
        pass

    return printData


def euobu_ca_config(child, command, *args):
    '''
   /*****************************************************
    Function Name: euobu_ca_config
    Description : This function is being used to check CAM packet transmission and reciption.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :
    Return Value : Integer value(packet number).
    Type : External API
    Example : obu ca_config -k
    Output: @Tx/Rx output and Tx/Rx count input


   ******************************************************/
    '''
    """ Author: Nilesh Guhe
    """

    command = command.split("obu")[1].strip()
    data = euobu_run_command_show(child, command)
    dictOut = {}
    if not 'stats:' in data:
        print(data)
        print("Received None and returning blank dict...")
        dictOut = {'tx_count': 0, 'rx_count': 0}
        dictOut = dictOut[args[0]]
        return dictOut
    else:
        print(data)
        data = re.sub(r"\t", "", data)
        data = data.split('\n')
        data = [x.strip(' ') for x in data]
        data.pop()
        data = data[2:]
        for i in data:
            i = i.split(':')
            i = [x.strip(' ') for x in i]
            dictValue = {i[0]: i[1]}
            dictOut.update(dictValue)
        dictOut = dictOut[args[0]]

        return dictOut


def euobu_backup_defaultConf(child, default="Yes"):
    '''
   /*****************************************************
    Function Name: euobu_backup_defaultConf
    Description : This function is being used take the backup of the default configaration.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)


    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu backup_deafultConf


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    child.sendline("")
    child.expect(config.OBUPMT)
    child.before
    child.sendline("ls /nojournal/")
    child.expect(config.OBUPMT)
    data = child.before
    if default == "No":
        child.sendline("cp -r /nojournal/configETSI.safe/* /etc/config/")
        sleep(2)
        child.expect(config.OBUPMT)
        data = str(child.before, "utf-8")
        if re.search(r"No such file or directory", data):
            print("Backup files may not exist....")
            return 0
        euobu_halt_run(child, 'obu eu_halt')
        euobu_halt_run(child, 'obu eu_run')
    else:
        if re.search(b"configETSI.safe", data):
            child.sendline("rm -rf /nojournal/configETSI.safe/")
        child.sendline("mkdir /nojournal/configETSI.safe")
        child.expect(config.OBUPMT)
        child.sendline("cp -r /etc/config/* /nojournal/configETSI.safe/")
        sleep(2)
        child.expect(config.OBUPMT)
        print("All files are copied successfully under /nojournal/configETSI.safe/ path")

    return 1


def euobu_ifconfig(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: euobu_ifconfig
    Description : This function is being used to view the information of the interfaces like Tx/Rx count.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command: obu euifconfig(@output,Interface name, input string)
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu euifconfig(@output,Interface name, input string)


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    try:
        intf = args[0]
        option = args[1]
    except IndexError:
        intf = 'ath1'
        option = 0
        print("Please provide option/interface...if interface is not provided then it will take default as a ath1")
    command = "ifconfig {}".format(intf)
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{} > euifconfig.txt".format(command))
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    obu_scp(child, "obu scp", "euifconfig.txt", dest_path)
    with open("{}/euifconfig.txt".format(dest_path), "r") as ifconfig:
        data = ifconfig.read()
    print(command)
    print(data)
    data_dict = {
        "HWaddr": re.search("HWaddr\s?((([\da-fA-F]){2}:?){6})", data).group(1),
        "TX packets": re.search("TX packets:(\d+)\s?", data).group(1),
        "RX packets": re.search("RX packets:(\d+)\s?", data).group(1),
    }
    try:
        value = data_dict[option]
    except KeyError:
        print("Please provide valid option or option is not provided")
    return value


def euobu_select_stack(child, cmd):
    '''
   /*****************************************************
    Function Name: euobu_select_stack
    Description : This function is being used to change the stack(US/EU).
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command: obu select_stack US/EU
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu select_stack US/EU


    ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    command = cmd.split("obu")[1].strip()
    child.sendline("")
    child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
    child.sendline("{}".format(command))
    sleep(15)
    child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)", timeout=100)
    changeStack = child.before
    changeStack = str(changeStack, "utf-8")
    child.sendcontrol("C")
    child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
    print(changeStack)
    if changeStack is None:
        print("Received None from select_stack command")
        return "-1"
    else:
        return 1


def euobu_stack_in_use(child, command):
    '''
   /*****************************************************
    Function Name:euobu_stack_in_use
    Description : This function is being used to check current stack.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command: obu stack_in_use {@output}
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu stack_in_use {@output}


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    command = command.split("obu")[1].strip()
    data = euobu_run_command_show(child, command)
    if data is None:
        print("Received None and returning None...")
        return None
    print(data)
    try:
        data = data.split('\n')
        data = data[1]
        Stack = data.split()
        Stack = Stack[3]
        return Stack
    except KeyError:
        print("Please check the received output")


def euobu_sys_process(child, cmd, *args):
    '''
   /*****************************************************
    Function Name:euobu_sys_process
    Description : This function is being used to checking the status of the process.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command: euobu ps OR euobu ps | grep {@output, process name}
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :euobu ps OR euobu ps | grep {@output, process name}


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    try:
        cmd = cmd.split("euobu")[1].strip()
        if len(args) > 0:
            command = cmd + " " + args[0]
            print("command:{}".format(command))
        else:
            command = cmd
        sleep(3)
        child.sendcontrol("C")
        child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
        print(command)
        child.sendline("{0}\r".format(command))
        sleep(2)
        child.expect("(US16SIQC:.+#)|(EU16SIQC:.+#)")
        databefore = child.before
        dataafter = child.after
        data = databefore + dataafter
        data = re.sub(r"\r", "", data.decode('utf-8'))
        data = re.sub(r"(\n)+", "\n", data)

        # data = euobu_run_command_show(child, command)
        if data is None:
            print("Received None and returning None...")
            return None
        print(data)
        pidValue = 0
        if len(args) > 0:
            try:
                data = data.split('\n')
                for line in data:
                    if 'root' in line and args[0] in line and not 'grep' in line:
                        line = line.split('root')
                        pidValue = int(line[0])
                        print("Process is running")
                        break
                if pidValue == 0:
                    print("Process is not running")
                    return -1
                else:
                    return pidValue
            except IndexError:
                print("Process may not be running")
                return -1
        return str(data)
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def euobu_eu_device_mode(child, cmd, *args, output=False):
    '''
   /*****************************************************
    Function Name:euobu_eu_device_mode
    Description : This function is being used to change/check device mode (ASD/RSU).
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command:obu eu_device_mode RSU/ASD
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu eu_device_mode RSU OR obu eu_device_mode ASD OR obu eu_device_mode {@output, ASD/RSU(device type)}


   ******************************************************/
   '''
    """ Author: Nilesh Guhe
    """

    command = cmd.split("obu")[1].strip()
    if len(args) == 0:
        command = command
    else:
        command = command + ' {}'.format(args[0])
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    child.expect(config.OBUPMT, timeout=100)
    deviceMode = child.before
    deviceMode = str(deviceMode, "utf-8")
    child.sendcontrol("C")
    child.expect(config.OBUPMT)
    if output:
        return deviceMode
    if not args:
        print(deviceMode)
        return 1
    print(deviceMode)
    device = re.search(r"Already.*((ASD)|(RSU))", deviceMode)
    device = device.group(1)
    return device
#    try:
#        if len(args) == 0:
#            return 1
#        else:
#            data = deviceMode.split('\n')
#            for temp in data:
#                if "Already" in temp:
#                    line = data.index(temp)
#            data = data[line]
#            data = data.split()
#            return data[2]
#    except IndexError:
#        print("May be args is not provided or Device mode did not change properly.. please check the output..")
#        return -1


def euobu_euv2xd(child, cmd):
    '''
   /*****************************************************
    Function Name:euobu_euv2xd
    Description : This function is being used to start the EUV2Xd process.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command:obu EUV2Xd
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu EUV2Xd


   ******************************************************/
    '''
    """ Author: Nilesh Guhe
    """

    #command = cmd.split("obu")[1].strip()
    command = "EUV2Xd &"
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("{}".format(command))
    sleep(3)
# if not re.search(r"EUV2Xd &", cmd):
# sleep(4)
# child.sendcontrol("C")
    child.expect(config.OBUPMT, timeout=10)
# if re.search(r"EUV2Xd &", cmd):
    child.sendline("")
    child.expect(config.OBUPMT)
    euv2xdOutput = child.before
    euv2xdOutput = str(euv2xdOutput, "utf-8")

    return euv2xdOutput


def euobu_killall(child, cmd, *args):
    '''
   /*****************************************************
    Function Name:euobu_killall
    Description : This function is being used to kill the particular process.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu).
    command: obu Killall
    Return Value : Sucess output OR Failure reason
                   Data type: String

    Type : External API

    Example :obu Killall

   ******************************************************/
   '''
    try:
        cmd = cmd.split("obu")[1].strip()
        child.sendline("")
        child.expect(config.OBUPMT)
        command = None
        if len(args) > 0:
            command = cmd + " " + args[0]
        else:
            command = cmd
        child.sendline("{}".format(command))
        sleep(3)
        child.expect(config.OBUPMT, timeout=10)
        data = child.before
        print(data)
        return 1
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def get_snmp_output(child, cmd, MIBFile=None, OID=None):

    if MIBFile and OID is None:
        print("MIBFile,OID is not provided")
        return None

    try:
        print("Connecting to snmp host:{} ".format(config.SYS_HOST))
        ssh_login = "ssh -q -o UserKnownHostsFile=/dev/null -o \
                                    StrictHostKeyChecking=no -p {0} {1}@{2}".format(22,
                                                                                    config.SYS_UNAME,
                                                                                    config.SYS_HOST
                                                                                    )
        snmp_command = f'./snmpget -v 3 -u {config.SNMP_Dict["SNMP3"]["UNAME"]} -A {config.SNMP_Dict["SNMP3"]["PASSWD"]} -X {config.SNMP_Dict["SNMP3"]["KEYPSWD"]} -a MD5 -x DES -l authPriv -m {config.SNMP_Dict["SNMP3"]["PATHMIB"]}{MIBFile} -t 10 {config.SNMP_Dict["SNMP3"]["IP"]} {OID}'
        print(snmp_command)
        print("ssh LOGIN:{}".format(ssh_login))

        for try_to_cnct in [1, 2, 3, 4]:
            try:
                host_child = pexpect.spawn(ssh_login)
                host_child.expect(r".*password: ")
                host_child.sendline("{}\r".format(config.SYS_PASSWORD))
                host_child.sendline("cd /home/savari/net-snmp-5.7.3/apps \r")
                host_child.sendline("{}\r".format(snmp_command))

                sleep(2)
                host_child.terminate()
                x = host_child.readlines()
                output_list = list(map(lambda i: i.decode(), x))
                host_child.close()
                try:
                    return output_list[-3]
                except IndexError:
                    print("Output doesn't fully formed")
                    return None
            except pexpect.TIMEOUT:
                print("Failed to connect in {} time".format(try_to_cnct))
                if try_to_cnct == 3:
                    host_child.close(force=True)
                    print(
                        "Time out while connecting to host:{}".format(config.SYS_HOST))
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
                continue
            except pexpect.EOF:
                print("Number of logins are three or check the connection")
                if try_to_cnct == 3:
                    return None
                sleep(10)
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except KeyError:
        print("SNMP host info is not defined in config file")
        return None


def set_snmp_output(child, cmd, MIBFile=None, OID=None, datatype=None, val=None):

    if MIBFile and OID is None:
        print("MIBFile,OID is not provided")
        return None

    try:
        print("Connecting to snmp host:{} ".format(config.SYS_HOST))
        ssh_login = "ssh -q -o UserKnownHostsFile=/dev/null -o \
                                    StrictHostKeyChecking=no -p {0} {1}@{2}".format(22,
                                                                                    config.SYS_UNAME,
                                                                                    config.SYS_HOST
                                                                                    )
        snmp_command = f'./snmpset -v 3 -u {config.SNMP_Dict["SNMP3"]["UNAME"]} -A {config.SNMP_Dict["SNMP3"]["PASSWD"]} -X {config.SNMP_Dict["SNMP3"]["KEYPSWD"]} -a MD5 -x DES -l authPriv -m {config.SNMP_Dict["SNMP3"]["PATHMIB"]}{MIBFile}  -t 10 {config.SNMP_Dict["SNMP3"]["IP"]} {OID} {datatype} {val}'
        print(snmp_command)
        print("ssh LOGIN:{}".format(ssh_login))

        for try_to_cnct in [1, 2, 3, 4]:
            try:
                host_child = pexpect.spawn(ssh_login)
                host_child.expect(r".*password: ")
                host_child.sendline("{}\r".format(config.SYS_PASSWORD))
                host_child.sendline("cd /home/savari/net-snmp-5.7.3/apps \r")
                host_child.sendline("{}\r".format(snmp_command))

                sleep(2)
                host_child.terminate()
                x = host_child.readlines()
                output_list = list(map(lambda i: i.decode(), x))
                host_child.close()
                try:
                    return output_list[-3]
                except IndexError:
                    print("Output doesn't fully formed")
                    return None
            except pexpect.TIMEOUT:
                print("Failed to connect in {} time".format(try_to_cnct))
                if try_to_cnct == 3:
                    host_child.close(force=True)
                    print(
                        "Time out while connecting to host:{}".format(config.SYS_HOST))
                    return None
                sleep(10)  # waiting for 10 sec before reconnecting again
                continue
            except pexpect.EOF:
                print("Number of logins are three or check the connection")
                if try_to_cnct == 3:
                    return None
                sleep(10)
    except (TypeError, AttributeError):
        print("Not connected to the device or child is unknown")
        return None
    except KeyError:
        print("SNMP host info is not defined in config file")
        return None


def euobu_XML_file_config_with_occurance(dest, filename, field_to_change, value, occurance):
    os.chdir(dest)
    with open(filename, 'r') as f:
        text = f.read()
    # compiled_string=f"<{field_to_change}>([/-_.\s:/0-9a-zA-Z]*)</{field_to_change}>"
    compiled_string = f"<{field_to_change}>(.*)</{field_to_change}>"
    x = re.finditer(compiled_string, text)
    cnt = 1
    replaced_text = None
    for i in x:
        if cnt != int(occurance):
            cnt += 1
            continue
        replaced_text = text[:i.span(
        )[0]]+f"<{field_to_change}>{value}</{field_to_change}>"+text[i.span()[1]:]
        break
    if replaced_text:
        with open(filename, 'w') as f:
            f.write(replaced_text)
        return 1
    else:
        print("Nothing is modified")
        return 0


def euobu_XMl_file_config(child, cmd, *args, occurance=0):
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field_to_change = args[1]
            value = args[2]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0

        if not occurance:
            if re.search(r"/", value):
                value = re.sub("/", r"\/", value)
                # print(value)
            command = f"sed -i 's/<{field_to_change}>[-/_\.\s:/0-9a-zA-Z]*<\/{field_to_change}>/<{field_to_change}>{value}<\/{field_to_change}>/' {path}"
            print(command)
            child.sendline(command)
            child.expect(config.OBUPMT)
            result = 1
        else:
            # it has multiple occurances in field so editing from local machine
            dest_path = os.path.abspath(config.SAFE_FW_PATH)
            obu_scp(child, cmd, path, dest_path)
            file_name = os.path.basename(path)
            result = euobu_XML_file_config_with_occurance(
                dest_path, file_name, field_to_change, value, occurance)
            if result:
                obu_scp_sys(child, cmd, dest_path+"/"+file_name,
                            "/".join(path.split("/")[:-1]))

            if re.search(r"/", value):
                value = re.sub("/", r"\/", value)

        if result:
            awk_cmd = "awk '/{}/ {{{}}}' {}".format(
                field_to_change, "print", path)
            child.sendline(awk_cmd)
            child.expect(config.OBUPMT)
            awk_data = str(child.before, "utf-8")
            print(awk_data)
            conf_val = re.search(
                f"<{field_to_change}>({value})<\/{field_to_change}>", awk_data).group(1)
            conf_val = conf_val.strip()
            print(conf_val)
            if re.search(r"/", conf_val):
                conf_val = re.sub("/", r"\/", conf_val)
            if value == conf_val:
                print("file successfully configured")
                return 1
            else:
                print("file not successfully configured")
                return "-1"
        else:
            return "-1"
    except IndexError:
        print("Please provide the valid number of arguments")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def euobu_XMl_file_config_get(child, cmd, *args, occurance=1):

    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field = args[1]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return None
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.OBUPMT)
        awk_data = str(child.before, "utf-8")
        print(awk_data)
        conf_val_iter = re.finditer(f"<{field}>(.*)<\/{field}>", awk_data)
        val_list = [i.group(1) for i in conf_val_iter]
        if val_list:
            try:
                return val_list[int(occurance)-1]
            except IndexError:
                print("invalid occurance value provided")
                return None
        else:
            print(f"invalid {field} tag provided")
            return None

    except IndexError:
        print("Please provide the valid number of arguments")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def WSMP_QOS_decoding(child, command, hex_dump=None, field=None):
    WSMP_QOS_Data = {}

    if not hex_dump:
        print("Provide Hex Dump")
        return -1

    QOS_Start = re.search("8800", hex_dump)
    QOS_Data = re.search("88dc", hex_dump)
    if QOS_Data and QOS_Start:
        hex_dump_verify = hex_dump[QOS_Start.start():QOS_Data.end()]
    else:
        print("802.11 QOS data is missing")
        return -1

    WSMP_QOS_Data["Version"] = int(hex_dump_verify[0:2], 16) & 3
    WSMP_QOS_Data["Type"] = (int(hex_dump_verify[0:2], 16) & 12) >> 2
    WSMP_QOS_Data["Subtype"] = (int(hex_dump_verify[0:2], 16) & 240) >> 4
    WSMP_QOS_Data["ToDS"] = int(hex_dump_verify[2:4], 16) & 1
    WSMP_QOS_Data["FromDS"] = int(hex_dump_verify[2:4], 16) & 2
    WSMP_QOS_Data["MoreFragments"] = int(hex_dump_verify[2:4], 16) & 4
    WSMP_QOS_Data["Retry"] = int(hex_dump_verify[2:4], 16) & 8
    WSMP_QOS_Data["Power management"] = (
        int(hex_dump_verify[2:4], 16) & 16) >> 4
    WSMP_QOS_Data["More data"] = (int(hex_dump_verify[2:4], 16) & 32) >> 5
    WSMP_QOS_Data["ProtectedFlag"] = (int(hex_dump_verify[2:4], 16) & 64) >> 6
    WSMP_QOS_Data["Order flag"] = (int(hex_dump_verify[2:4], 16) & 128) >> 7
    WSMP_QOS_Data["Duration"] = int(hex_dump_verify[4:8], 16)
    WSMP_QOS_Data["Destination"] = hex_dump_verify[8:20]
    WSMP_QOS_Data["Source"] = hex_dump_verify[20:32]
    WSMP_QOS_Data["BSSID"] = hex_dump_verify[32:44]
    WSMP_QOS_Data["Sequencenumber"] = (
        int(hex_dump_verify[46:48] + hex_dump_verify[44:46], 16) & 65520) >> 4
    WSMP_QOS_Data["Fragmentnumber"] = int(hex_dump_verify[44:46], 16) & 15
    WSMP_QOS_Data["TID"] = int(hex_dump_verify[48:50], 16) & 7
    WSMP_QOS_Data["EOSP"] = (int(hex_dump_verify[48:50], 16) & 16) >> 7
    WSMP_QOS_Data["AckPolicy"] = (int(hex_dump_verify[48:50], 16) & 96) >> 5
    WSMP_QOS_Data["PayloadType"] = (int(hex_dump_verify[48:50], 16) & 128) >> 7
    WSMP_QOS_Data["TxOP Duration"] = int(hex_dump_verify[50:52], 16)

    if field:
        try:
            return WSMP_QOS_Data[field]
        except KeyError:
            print("Provide valid field for decoding")
            return "-1"
    else:
        print("No field is provided\n. Print complete dictionary")
        print(WSMP_QOS_Data)
        return None


def euobu_dsrc_get_config(child, cmd, option=None):
    '''
        /*********************************************************************
        Function Name: euobu_dsrc_get_config
                Description : This function is being used to run euobu_dsrc_get_config command in EU obu.
                              (refer api_wrapper.txt for associated commands with the API)
                Input Parameters :
                child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
                command  : euobu dsrc_get_config ath1 {option=Tx_Power}
                           euobu dsrc_get_config ath1

                 Return Value : Result of the command if no option is provided else returns param value.
                               Data type: String

        **************************************************************************/
        '''
    dsrc_dict = {}
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        command = cmd.split("euobu")[1].strip()
        command = f'{command.split(" ")[:-1][0]} -i {command.split(" ")[-1]}'
        print(command)
        child.sendline(command)
        child.expect(config.OBUPMT)
        data = child.before
        data = str(data, "utf-8")
        if not option:
            print("Required value is not provided. Printing output for command")
            return data
        else:
            try:
                dsrc_dict["Radio_Mode"] = re.search(
                    "Radio Mode :\s(\d)+", data).group(1)
                dsrc_dict["EPD_Status"] = re.search(
                    "EPD Status :\s(\d+)", data).group(1)
                dsrc_dict["Channel_Index"] = re.search(
                    "Channel Index :\s(\d+)", data).group(1)
                dsrc_dict["Frequency"] = re.search(
                    "Frequency :\s(\d+)", data).group(1)
                dsrc_dict["Duration"] = re.search(
                    "Duration :\s(\d+)", data).group(1)
                dsrc_dict["Guard_Interval"] = re.search(
                    "Guard Interval :\s(\d+)", data).group(1)
                dsrc_dict["Bandwidth"] = re.search(
                    "Bandwidth :\s(\d+)", data).group(1)
                dsrc_dict["Tx_Power"] = re.search(
                    "Tx Power :\s(\d+)", data).group(1)
                dsrc_dict["channel_number"] = int(
                    (int(dsrc_dict["Frequency"].strip())-5000)/5)
            except AttributeError:
                print("Output is not fully formed")
                # print(data)
                return -1
            try:
                return dsrc_dict[option]
            except KeyError:
                print("Provide valid key value")
                return -1

    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def euobu_dsrc_get_config_obsolete(child, cmd, option=None):
    '''
        /*********************************************************************
        Function Name: euobu_dsrc_get_config
        Description : This function is being used to run euobu_dsrc_get_config command in EU obu.
                              (refer api_wrapper.txt for associated commands with the API)
        Input Parameters :
        child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
        command  : euobu dsrc_get_config ath1 {option=Tx_Power}
                   euobu dsrc_get_config ath1

        Return Value : Result of the command if no option is provided else returns param value.
        Data type: String

        **************************************************************************/
        '''
    dsrc_dict = {}
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        command = cmd.split("euobu")[1].strip()
        command = f'{command.split(" ")[:-1][0]} -i {command.split(" ")[-1]}'
        print(command)
        child.sendline(command)
        child.expect(config.OBUPMT)
        data = child.before
        data = str(data, "utf-8")
        if not option:
            print("Required value is not provided. Printing output for command")
            return data
        else:
            try:
                dsrc_dict["Radio_Mode"] = re.search(
                    "Radio Mode :(\d+)", data).group(1)
                dsrc_dict["EPD_Status"] = re.search(
                    "EPD Status :(.*)", data).group(1)
                dsrc_dict["Channel_Index"] = re.search(
                    "Channel Index :(.*)", data).group(1)
                dsrc_dict["Frequency"] = re.search(
                    "Frequency :(.*)", data).group(1)
                dsrc_dict["Duration"] = re.search(
                    "Duration :(.*)\r", data).group(1)
                dsrc_dict["Guard_Interval"] = re.search(
                    "Guard Interval :(.*)\r", data).group(1)
                dsrc_dict["Bandwidth"] = re.search(
                    "Bandwidth :(.*)\r", data).group(1)
                dsrc_dict["Tx_Power"] = re.search(
                    "Tx Power :(.*)\r", data).group(1)
                dsrc_dict["channel_number"] = int(
                    (int(dsrc_dict["Frequency"].strip())-5000)/5)
            except AttributeError:
                print("Output is not fully formed")
                print(data)
                return None
            try:
                return dsrc_dict[option]
            except KeyError:
                print("Provide valid key value")
                return None

    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def obu_ping_statistics(child, cmd, *args, count=5):
    """
       /*****************************************************
        Function Name: obu_ping_statistics
        Description : This function is being used to ping an ip address.
                      (refer api_wrapper.txt for associated commands with the API)
        Input Parameters :
        child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
        command  : obu ping {ipaddress,<ipaddress>,option,count}
                   obu ping6 {ipaddress,<ipaddress>,option,count}


         Return Value : Result of the command or Failure reason.
                       Data type: String

        Type : External API

        Example : obu ping
        Output:
    PING 10.0.0.229 (10.0.0.229): 56 data bytes
    64 bytes from 10.0.0.229: seq=0 ttl=64 time=0.482 ms
    64 bytes from 10.0.0.229: seq=1 ttl=64 time=0.327 ms
    64 bytes from 10.0.0.229: seq=2 ttl=64 time=0.328 ms
    64 bytes from 10.0.0.229: seq=3 ttl=64 time=0.299 ms
    64 bytes from 10.0.0.229: seq=4 ttl=64 time=0.331 ms

    --- 10.0.0.229 ping statistics ---
    5 packets transmitted, 5 packets received, 0% packet loss
    round-trip min/avg/max = 0.299/0.353/0.482 ms

       ******************************************************/
    """

    command = cmd.split("obu")[1].strip()

    if args[0] == "ipaddress":
        ipaddress = args[1].split("/")[0]
    else:
        print("ipaddress not provided")
        return -1
    try:
        option = args[2]
    except IndexError:
        option = 0

    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline(
        "{} {}  -c {} > ping.txt".format(command, ipaddress, int(count)))
    sleep(int(count))
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    obu_scp(child, "obu scp", "ping.txt", dest_path)
    with open("{}/ping.txt".format(dest_path), "r") as ping:
        data = ping.read()
    if not data:
        print("Bad ip address provided")
        return -1

    data_dict = {
        'packets_transmitted': re.search(r"([\d]*)\s(packets transmitted)", data),
        'packets_recieved': re.search(r"([\d]*)\s(packets received)", data),
        'packetloss': re.search(r"([\d]*)%\spacket loss", data),
        'round_trip_min': re.search(r"round-trip min/avg/max = ([\d.]*)", data),
        'round_trip_avg': re.search(r"round-trip min/avg/max = .*\/([\d.]*)\/.*", data),
        'round_trip_max': re.search(r"round-trip min/avg/max = .*\/.*\/([\d.]*)", data)
    }

    if not option:
        print("No option provided, displaying ping output")
        print(data)
        return 0
    try:
        re_object = data_dict[option]
        value = re_object.group(1)
    except (KeyError, AttributeError):
        print("Please provide valid option or Pattern not found")
        return "-1"
    return int(value) if value.isnumeric() else value


def obu_gracefull_shutdown_func(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_gracefull_shutdown_func
    Description : This function is being used to Graceful shutdown the OBU board.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :   obu graceshut

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu graceshut


   ******************************************************/
   '''
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("SavariGraceshutd")
    sleep(10)
    child.terminate(force=True)
    data = child.readlines()
    # data = list(map(lambda i: i.decode(), data))
    data = [i.decode() for i in data]
    printdata = "\n".join(data)
    print(printdata)
    return printdata

###########


def obu_acfinfo(child, cmd, *args):

    try:
        path_to_acf_file = args[0]
        option = args[1] if len(args) > 1 else ""
    except IndexError:
        print("Provide path for acf file and option to be fetched")
        return -1
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline(f"acfInfo {path_to_acf_file}*.acf  0 > acfInfo.txt \r")
        sleep(2)
        child.expect(config.OBUPMT)
        child.sendline("cat acfInfo.txt")
        child.expect(config.OBUPMT)
        acf_messy_data = child.before
        child.sendline("rm acfInfo.txt")
        child.expect(config.OBUPMT)
        data = str(acf_messy_data, "utf-8")
        if re.search("File input error", data):
            print(f"acf file doesn't exist in {path_to_acf_file}")
            return -1
        if not option:
            print("No option provided, Returning command output")
            return data
        data_dict = {
            "certid10": re.search(r"certid10:\s([\da-z\s]+)", data),
            "version": re.search(r"version:\s+([\d]+)", data),
            "type": re.search(r"type:\s+([a-zA-Z]+)", data),
            "issuer": re.search(r"issuer:\s+([\da-z\s]+)\r\n", data),
            "toBeSigned_certId": re.search(r"certId:\s+([a-zA-Z:=\d{}\s,]+)[\s+]cracaId:", data),
            "toBeSigned_cracaId": re.search(r"cracaId:\s+([\d{2}\s]+)", data),
            "toBeSigned_crlSeries": re.search(r"crlSeries:\s+([\d]+)", data),
            "validityPeriod_start": re.search(r"start:\s+([\d]+)", data),
            "validityPeriod_duration": re.search(r"duration:\s+([\d\sa-zA-Z]+)\n", data),
            "validityPeriod_expiration": re.search(r"expiration:\s+([\da-z]+)", data),
            "region": re.search(r"region:\s+([\da-z]+)", data),
            "assuranceLevel": re.search(r"assuranceLevel:([\d\s\(\)x]+)", data),
            "appPermissions": re.search(r"appPermissions:[\s\n]+([a-z()\d]+)", data),
            "certIssuePermissions": re.search(r"certIssuePermissions:\s+([\da-z\s]+)\n", data),
            "certReqPermissions": re.search(r"certReqPermissions:\s+([\da-z\s]+)\n", data),
            "canRequestRollover": re.search(r"canRequestRollover:\s+([\da-z\s]+)\n", data),
            "encryptionKey": re.search(r"encryptionKey:\s+([\da-z\s]+)\n", data),
            "verifyKeyIndicator": re.search(r"verifyKeyIndicator:\s+([a-zA-Z\s]+)\n", data),
            # ?
            "encryptionKey": re.search(r"encryptionKey:\s+([\da-z\s]+)\n", data),
            "key_type_x": re.search(r"x:\s+([\da-z\s]+)\n", data),
            "key_type_2": re.search(r"key type[:\w\s]+2:\s+([\dA-Za-z\s_]+)\n", data)}

        # for key,value in data_dict.items():
        #     try:
        #         print(f"{key}------------->{value.group(1)}")
        #     except:
        #         print(f"Not valid for {key}")
        try:
            value = data_dict[option]
        except KeyError:
            print("Provide valid key")
            return -1
        if value:
            return value.group(1).strip()
        else:
            return None
    except pexpect.TIMEOUT:
        print("Timeout happened in euobu_acfInfo function")
        return None

###########


def euobu_acfinfo(child, cmd, *args):
    try:
        path_to_acf_file = args[0]
        option = args[1]
    except IndexError:
        print("Provide path for acf file and option to be fetched")
        return -1
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        child.sendline(f"acfInfo {path_to_acf_file}*.acf  0 > acfInfo.txt \r")
        sleep(2)
        child.expect(config.OBUPMT)
        child.sendline("cat acfInfo.txt")
        child.expect(config.OBUPMT)
        acf_messy_data = child.before
        child.sendline("rm acfInfo.txt")
        child.expect(config.OBUPMT)
        data = str(acf_messy_data, "utf-8")
        if re.search("File input error", data):
            print(f"acf file doesn't exist in {path_to_acf_file}")
            return -1
        data_dict = {
            "certid8": re.search(r"certid8:\s([\da-z\s]+)", data),
            "Version": re.search(r"Version:\s+([\d]+)", data),
            "SignerType": re.search(r"SignerType:\s+([\da-z]+)", data),
            "digest": re.search(r"digest:\s+([\da-z\s]+)", data),
            "Subject_Info_Type": re.search(r"\s+Type:\s+([_\da-z]+)", data),
            "Subject_Info_Name": re.search(r"Name:\s+([\da-z\s]+)", data),
            "Subject_attributes_Algorithm": re.search(r"Algorithm:\s+([\da-z\s]+)", data),
            "Subject_attributes_EccPoint_Type":
            re.search(r"EccPoint:[:\w\s]+Type:\s+([_\dA-Za-z\s]+)\n", data),
            "Subject_attributes_EccPoint_x": re.search(r"x:\s+([\da-z\s]+)\n", data),
            "aid-ssp_aid": re.search(r"aid:\s+([\d]+)", data),
            "aid-ssp_ssp": re.search(r"ssp:\s+([\d]:(.)+)", data),
            "Validity_Restrictions_StartValidity":
            re.search(r"StartValidity:\s+([\da-z]+)", data),
            "Validity_Restrictions_endValidity": re.search(r"EndValidity:\s+([\da-z]+)", data),
            "Validity_Restrictions_Region": re.search(r"Region:\s+([\dA-Za-z\s]+)\n", data),
            "Signature_Algorithm": re.search(r"Signature:[:\w\s]+Algorithm:\s+([\da-z\s]+)\n", data),
            "Signature_EccPoint_Type": re.search(r"Signature[:\w\s]+Type:\s+([_\dA-Za-z\s]+)\n", data),
            "Signature_EccPoint_x": re.search(r"Signature[:\w\s]+x:\s+([\da-z\s]+)\n", data),
            "Signature_EccPoint_s": re.search(r"Signature[:\w\s]+s:\s+([\da-z\s]+)\n", data)}

        # for key,value in data_dict.items():
        #     try:
        #         print(f"{key}------------->{value.group(1)}")
        #     except:
        #         print(f"Not valid for {key}")
        try:
            value = data_dict[option]
        except KeyError:
            print("Provide valid key")
            return -1
        if value:
            return value.group(1).strip()
        else:
            return None
    except pexpect.TIMEOUT:
        print("Timeout happened in euobu_acfInfo function")
        return None


def euobu_etsifacility_stats(child, command, *args):
    '''
   /*****************************************************
    Function Name: euobu_etsifacility_stats
    Description : This function is being used to get CAM or DENM TX, RX count
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu etsifacility_stats -d{DENM} .
               obu etsifacility_stats -c{CAM}
    Return Value : String data(Result of the command or Failure reason).
    Type : External API
    Example : obu gntool set_gnaddr


   ******************************************************/
    '''

    try:
        option = args[0]
    except IndexError:
        option = None
    command = command.split("obu")[1].strip()
    data = euobu_run_command_show(child, command)
    if data is None:
        print("Received None and returning None...")
        return None
    print(data)
    if re.search("Failed to receive stats", data):
        print("Enable CAM/DENM service to see stats")
        return -1
    if option is None:
        return data
    keys = re.findall("\s+([a-zA-Z\s]+):", data)
    if re.search("-d", command):
        # Added new transmit stats for different denm types(NEW,UPDATE,CANCEL,NEGATION)
        TX_count_str = ['NEW_DENM_Transmit count', 'UPDATE_DENM_Transmit count', 'CANCEL_DENM_Transmit count',
                        'NEGATION_DENM_Transmit count']
        keys[keys.index('NEW DENM') + 1], keys[keys.index('UPDATE DENM') + 1], keys[keys.index('CANCEL DENM') + 1], \
            keys[
            keys.index('NEGATION DENM') + 1] = TX_count_str
    values = re.findall(":\s*([-\d/:\s]+)", data)
    data_dict = {k: v.strip() for k, v in zip(keys, values)}
    try:
        return data_dict[option]
    except KeyError:
        print("Please provide valid option or Pattern not found")
        return "-1"


def obu_meminfo(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_meminfo
    Description : This function is being used to know the inforamation of the system memory.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  : obu meminfo

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu meminfo
    Output:
cat /proc/meminfo
MemTotal:        1804844 kB
MemFree:         1754296 kB
MemAvailable:    1679032 kB
Buffers:             468 kB
Cached:            11004 kB
SwapCached:            0 kB
Active:            13408 kB
Inactive:           4728 kB
Active(anon):       6664 kB
Inactive(anon):      100 kB
Active(file):       6744 kB
Inactive(file):     4628 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                48 kB
Writeback:             0 kB
AnonPages:          6680 kB
Mapped:            10764 kB
Shmem:               108 kB
Slab:              14516 kB
SReclaimable:       1916 kB
SUnreclaim:        12600 kB
KernelStack:         824 kB
PageTables:          612 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:      902420 kB
Committed_AS:     118680 kB
VmallocTotal:     245760 kB
VmallocUsed:       19604 kB
VmallocChunk:     178100 kB




   ******************************************************/
   '''
    command = 'cat /proc/meminfo'
    try:
        option = args[0]
    except IndexError:
        option = None
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline(f"{command} > meminfo.txt")
    child.expect(config.OBUPMT)
    dest_path = os.path.abspath(config.SAFE_FW_PATH)
    print("DEST_PATH:{}".format(dest_path))
    dest_path = "{}/resource/files".format(dest_path)
    obu_scp(child, "obu scp", "meminfo.txt", dest_path)
    with open("{}/meminfo.txt".format(dest_path), "r") as meminfo:
        data = meminfo.read()
    data_dict = {
        "MemTotal": re.search(r"MemTotal:\s+(\d+)", data),
        "MemFree": re.search(r"MemFree:\s+(\d+)", data),
        "MemAvailable": re.search(r"MemAvailable:\s+(\d+)", data),
        "Buffers": re.search(r"Buffers:\s+(\d+)", data),
        "Cached": re.search(r"Cached:\s+(\d+)", data),
    }
    print("option:", option)
    if not option:
        print("No option provided, displaying meminfo output")
        print(data)
        return 0
    try:
        re_object = data_dict[option]
        value = re_object.group(1)
    except (KeyError, AttributeError):
        print("Please provide valid option or Pattern not found")
        return "-1"
    return int(value) if value.isnumeric() else value


def eu_v2x_play(child, cmd, *args, interval=None, f_data=None):
    try:
        if interval:
            child_list = args[::3]
            command_list = args[1::3]
            sample_file_list = args[2::3]
            for c in child_list:
                c.sendline("ls -l")
                c.expect(config.OBUPMT, timeout=10)
                ls_data = c.before
                ls_data = str(ls_data, "utf-8")
                if not re.search("v2x_play", ls_data):
                    src_file_path = f"resource/v2x_play"
                    obu_scp_sys(c, "obu scp sys", src_file_path, "/root")
            for index, c in enumerate(child_list):
                c.sendline("")
                c.expect(config.OBUPMT)
                c.sendline(f"chmod 777 v2x_play")
                c.expect(config.OBUPMT)
                command = f"./{command_list[index]} -p {sample_file_list[index]} -t {int(interval)} > v2x_play_output.txt 1>&2"
                print(command)
                c.sendline(command)
            for index, c in enumerate(child_list):
                try:
                    c.expect(config.OBUPMT, timeout=1000)
                    data = str(child.before, "utf-8")
                    if re.search("failed to init CAN", data) or re.search("failed to init GNSS", data) or re.search("failed to send", data):
                        print("GNSS/CANd is not killed properly or provided value is invalid")
                        print (data)
                        return -1
                except pexpect.TIMEOUT:
                    print("Time out happened in euobu_v2x_play ...")
                    return None
            if f_data :
                        return data
            else :
                        return 1
        else:
            print("Provide interval argument")
            return -1

    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Time out happened in euobu_v2x_play ...")
        return None


def euobu_CAM_decoding_PCAP(child, cmd, pcap_file, field=None, index=0):
    index = int(index)
    cam_header_dict = {}
    try:
        pcap_reader = pyshark.FileCapture(
            f"{config.SAFE_FW_PATH}/resource/pcap_files/{pcap_file}", display_filter="cam")
    except FileNotFoundError:
        print(f"{pcap_file} not found ")
        return -1
    try:
        cam_header_dict = {
            "protocol version": pcap_reader[index].cam.get_field_value("protocolversion"),
            "message id": pcap_reader[index].cam.get_field_value("messageid"),
            "station id": pcap_reader[index].cam.get_field_value("stationid"),
            "generation delta time": pcap_reader[index].cam.get_field_value("generationdeltatime"),
            "station type": pcap_reader[index].cam.get_field_value("stationtype"),
            "latitude": pcap_reader[index].cam.get_field_value("latitude"),
            "longitude": pcap_reader[index].cam.get_field_value("longitude"),
            "semi major confidence": pcap_reader[index].cam.get_field_value("semimajorconfidence"),
            "semi minor confidence": pcap_reader[index].cam.get_field_value("semiminorconfidence"),
            "semi major orientation": pcap_reader[index].cam.get_field_value("semimajororientation"),
            "altitude": pcap_reader[index].cam.get_field_value("altitudevalue"),
            "high frequency container": pcap_reader[index].cam.get_field_value("highfrequencycontainer"),
            "heading value": pcap_reader[index].cam.get_field_value("headingvalue"),
            "heading confidence": pcap_reader[index].cam.get_field_value("headingconfidence"),
            "speed": pcap_reader[index].cam.get_field_value("speedvalue"),
            "speed confidence": pcap_reader[index].cam.get_field_value("speedconfidence"),
            "drive direction": pcap_reader[index].cam.get_field_value("drivedirection"),
            "vehicle length": pcap_reader[index].cam.get_field_value("vehiclelengthvalue"),
            "vehicle length confidence indication": pcap_reader[index].cam.get_field_value(
                "vehiclelengthconfidenceindication"),
            "vehicle width": pcap_reader[index].cam.get_field_value("vehiclewidth"),
            "longitudinal acceleration": pcap_reader[index].cam.get_field_value("longitudinalaccelerationvalue"),
            "longitudinal acceleration confidence": pcap_reader[index].cam.get_field_value(
                "longitudinalaccelerationconfidence"),
            "curvature": pcap_reader[index].cam.get_field_value("curvaturevalue"),
            "curvature confidence": pcap_reader[index].cam.get_field_value("curvatureconfidence"),
            "yawrate": pcap_reader[index].cam.get_field_value("yawratevalue"),
            "yawrate confidence": pcap_reader[index].cam.get_field_value("yawrateconfidence"),
            "lane position": pcap_reader[index].cam.get_field_value("laneposition"),
            "low frequency container": pcap_reader[index].cam.get_field_value("lowfrequencycontainer"),
            "vehiclerole": pcap_reader[index].cam.get_field_value("vehiclerole"),
            "exterior lights": pcap_reader[index].cam.get_field_value("exteriorlights"),
            "per_sequence_of_length": pcap_reader[index].cam.get_field_value("per_sequence_of_length"),
            "path history": pcap_reader[index].cam.get_field_value("pathhistory"),
            "delta latitude": pcap_reader[index].cam.get_field_value("deltalatitude"),
            "delta longitude": pcap_reader[index].cam.get_field_value("deltalongitude"),
            "delta altitude": pcap_reader[index].cam.get_field_value("deltaaltitude"),
            "path delta time": pcap_reader[index].cam.get_field_value("pathdeltatime"),
        }

    except AttributeError:
        print(f"provide valid CAM packet."
              f"pcap file has following layers {pcap_reader[index].layers}")
        pcap_reader.close()
        return -1
    except KeyError:
        print(f"Provide valid index {index}"
              f"Total number of packets captured {len(list(pcap_reader))}")
        pcap_reader.close()
        return -1
    if field:
        try:
            pcap_reader.close()
            return cam_header_dict[field]
        except KeyError:
            print("Provide valid key to be fetched")
            pcap_reader.close()
            return -1
    else:
        print("provide header field to be fetched")
        pcap_reader.close()
        return -1


def euobu_DENM_decoding_PCAP(child, cmd, pcap_file, field=None, index=0):
    index = int(index)
    denm_header_dict = {}
    try:
        pcap_reader = pyshark.FileCapture(
            f"{config.SAFE_FW_PATH}/resource/pcap_files/{pcap_file}", display_filter="denm")
    except FileNotFoundError:
        print(f"{pcap_file} not found ")
        return -1
    try:
        denm_header_dict = {
            "gbc seq number": pcap_reader[index].gn.sn,
            "protocol version": pcap_reader[index].denm.get_field_value("protocolversion"),
            "message id": pcap_reader[index].denm.get_field_value("messageid"),
            "station id": pcap_reader[index].denm.get_field_value("stationid"),
            "per_optional_field_bit": pcap_reader[index].denm.get_field_value("per_optional_field_bit"),
            "per_extension_bit": pcap_reader[index].denm.get_field_value("per_extension_bit"),
            "originating station id": pcap_reader[index].denm.get_field_value("originatingstationid"),
            "sequence number": pcap_reader[index].denm.get_field_value("sequencenumber"),
            "detectiontime": pcap_reader[index].denm.get_field_value("detectiontime"),
            "referencetime": pcap_reader[index].denm.get_field_value("referencetime"),
            "latitude": pcap_reader[index].denm.get_field_value("latitude"),
            "longitude": pcap_reader[index].denm.get_field_value("longitude"),
            "semi major confidence": pcap_reader[index].denm.get_field_value("semimajorconfidence"),
            "semi minor confidence": pcap_reader[index].denm.get_field_value("semiminorconfidence"),
            "semi major orientation": pcap_reader[index].denm.get_field_value("semimajororientation"),
            "altitude": pcap_reader[index].denm.get_field_value("altitudevalue"),
            "per_enum_index": pcap_reader[index].denm.get_field_value("per_enum_index"),
            "altitude confidence": pcap_reader[index].denm.get_field_value("altitudeconfidence"),
            "relevance distance": pcap_reader[index].denm.get_field_value("relevancedistance"),
            "relevancetrafficdirection": pcap_reader[index].denm.get_field_value(
                "relevancetrafficdirection"),
            "validity duration": pcap_reader[index].denm.get_field_value("validityduration"),
            "station type": pcap_reader[index].denm.get_field_value("stationtype"),
            "information quality": pcap_reader[index].denm.get_field_value(
                "informationquality"),
            "cause code": pcap_reader[index].denm.get_field_value("causecode"),
            "subcause code": pcap_reader[index].denm.get_field_value("subcausecode"),
            "speed": pcap_reader[index].denm.get_field_value("speedvalue"),
            "speed confidence": pcap_reader[index].denm.get_field_value("speedconfidence"),
            "per_sequence_of_length": pcap_reader[index].denm.get_field_value("per_sequence_of_length"),
            "traces": pcap_reader[index].denm.get_field_value("traces"),
            "path history": pcap_reader[index].denm.get_field_value("pathhistory"),
            "delta latitude": pcap_reader[index].denm.get_field_value("deltalatitude"),
            "delta longitude": pcap_reader[index].denm.get_field_value("deltalongitude"),
            "delta altitude": pcap_reader[index].denm.get_field_value("deltaaltitude"),
            "alacarte_element": pcap_reader[index].denm.get_field_value("alacarte_element"),
            "stationaryvehicle_element": pcap_reader[index].denm.get_field_value("stationaryvehicle_element"),
            "stationary since": pcap_reader[index].denm.get_field_value("stationarysince"),

        }

    except AttributeError:
        print(f"provide valid DENM packet."
              f"pcap file has following layers {pcap_reader[index].layers}")
        pcap_reader.close()
        return -1
    except KeyError:
        print(f"Provide valid index {index}"
              f"Total number of packets captured {len(list(pcap_reader))}")
        pcap_reader.close()
        return -1
    if field:
        try:
            pcap_reader.close()
            return denm_header_dict[field]
        except KeyError:
            print("Provide valid key to be fetched")
            pcap_reader.close()
            return -1
    else:
        print("provide header field to be fetched")
        pcap_reader.close()
        return -1


def rsu_get_newer_syslog_file(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: obu_get_newer_pcap_file
    Description : This function is being used to get the latest log files.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  rsu get newer syslog file

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : rsu get newer syslog file
   ******************************************************/
    '''
    try:
        path = args[0]
    except IndexError:
        print("Please provide the path name")
        return "-1"
    path = os.path.abspath(path)
    command = "ls -ltr {}/syslog* | tail -n 1".format(path)
    child.sendline(command)
    child.expect(config.SHELLPMT)
    data = str(child.before, "utf-8")
    print(data)
    syslog = re.search(r"syslog[_\d]*\.txt", data)
    try:
        syslog_name = syslog.group()
    except AttributeError:
        print("No syslog found")
        return "-1"
    return syslog_name


def rsu_file_config_get(child, cmd, *args):
    '''
   /*****************************************************
    Function Name: rsu_file_config
    Description : This function is being used to get the configarations in the config file.
                  (refer api_wrapper.txt for associated commands with the API)
    Input Parameters :ig
    child : child (It is the spawn object of pexpect. We can say it as connection between system and obu/rsu)
    command  :  rsu file config get

     Return Value : Result of the command or Failure reason.
                   Data type: String

    Type : External API

    Example : obu file config  get

   ******************************************************/
   '''
    try:
        child.sendline("")
        child.expect(config.SHELLPMT)
        try:
            path = args[0]
            field_to_get = args[1]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_get, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.SHELLPMT)
        awk_data = str(child.before, "utf-8")
        print(awk_data)
        awk_data_str = re.split(r"\n", awk_data)
        conf_str = [line for line in awk_data_str if re.search(
            r"^{}".format(field_to_get), line)]
        print(conf_str)
        conf_val = re.search(
            r'=\s{0,}"?([\da-zA-Z_.-\/]+)"?', conf_str[0]).group(1)
        conf_val = conf_val.strip()
        print(conf_val)
        return conf_val
    except IndexError:
        print("Please provide the valid argument to fetch")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in rsu_file_config function")
        return None


def coc_tcia_start(child, cmd, *args):
    try:
        child.expect(config.SHELLPMT, timeout=4)
    except pexpect.TIMEOUT:
        pass
    child.sendline("ps | grep /usr/local/bin/savari/coc_tcia | wc -l")
    child.expect(config.SHELLPMT)
    data = str(child.before, "utf-8")
    print(data)
    try:
        coc_app_cnt = re.search(
            r"coc_tcia \| wc -l[\s\r\n]+(\d+)", data).group(1)
        if int(coc_app_cnt) > 1:
            print("Num of coc_tcia instances:{}".format(coc_app_cnt))
            print("coc_tcia is already running")
        else:
            print("Starting coc_tcia")
            child.sendline("/usr/local/bin/savari/coc_tcia &")
            child.sendline("\r\n")
            child.expect(config.SHELLPMT)
    except (AttributeError, TypeError):
        print(traceback.format_exc())
        print("coc_tcia is not running")
    return data
