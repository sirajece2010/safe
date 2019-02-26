'''
    File name: main.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''

import wrapper
import subprocess as sp
import genLib
import logging
from colorama import Fore
import libKPI
import pandas as pd

libRSE = wrapper.libRSE  # module
bsm = wrapper.api_wrapper.bsm  # module
wrapper_func = wrapper.wrapper_func  # func
config = libRSE.config  # module
re = libRSE.re  # module
os = libRSE.os  # module
obu_connect_to_device = libRSE.obu_connect_to_device  # func
connect_to_device = libRSE.connect_to_device  # func
logger_wrapper = libRSE.logger_wrapper  # func
logger_check_status = libRSE.logger_check_status  # func
logger_config = libRSE.logger_config  # func
jira_attributes_func = libRSE.jira_attributes_func  # func
obu_reset_func = libRSE.obu_reset_func  # func
start_of_testcase = libRSE.start_of_testcase  # func
end_of_testcase = libRSE.end_of_testcase  # func
DEVICE = None

# The below three functions used to clear dmesg and meminfo info


def obu_cleanup_func(child, device, *args):
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("dmesg -C")
    child.expect(config.OBUPMT)
    return


def euobu_cleanup_func(child, device, *args):
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("dmesg -C")
    child.expect(config.OBUPMT)
    return


def rsu_cleanup_func(child, device, *args):
    libRSE.direct_to_shell_mode(child, "direct to shell mode", device)
    child.sendline("dmesg -C\r")
    child.expect(config.SHELLPMT)
    libRSE.exit_fun(child, "exit")
    return


@logger_wrapper
def command(child, cmd, *args, **kwargs):
    global DEVICE
    DEVICE = child
    print("command:{}".format(cmd))
    cmd = re.sub(r"(\s+)", " ", cmd)
    data = re.split(r" ", cmd, 1)
    if args or kwargs != 0:
        print(*args)
        if kwargs:
            print(kwargs)
        output = wrapper_func(data[0], cmd)(child, cmd, *args, **kwargs)
        return output
    else:
        output = wrapper_func(data[0], cmd)(child, cmd)


def genFunc(cmd, *args):
    gen_cmd_db = {
        "gen value at index": genLib.value_at_index,
        "gen math operation": genLib.math_operation_func,
        "gen string operation": genLib.string_operation_func
    }
    return gen_cmd_db[cmd](*args)


def kpi_genFunc(cmd, *args):
    gen_cmd_db = {
        "file conv": libKPI.file_converter,
        "csv merge": libKPI.csv_merge,
        "r print": libKPI.rb_print,
        "clr file": libKPI.clr_file,
        "dict var": libKPI.get_from_dict,
        "utc loc": libKPI.utc_2_local,
        "mp extr": libKPI.mp_extr,
        "dmips conv": libKPI.dmips_conv,
        "csv plot": libKPI.csv_plotter,
        "kpi nequal": libKPI.kpi_nequal,
        "idle conv": libKPI.idle_to_used,
        "rnm header": libKPI.csv_header,
        "csv add": libKPI.csv_adder
    }
    return gen_cmd_db[cmd](*args)


def in_fun(output, value, index=None):
    if type(output) is str:
        if type(value) is str:
            if re.search(re.escape(value), output, re.I):
                print("\"{}\" is present in \"{}\"".format(value, output))
                return 1
            else:
                print("\"{}\" is not present in \"{}\"".format(value, output))
                return 0
        for item in value:
            if re.search(item, output, re.I):
                print("\"{}\" is present in \"{}\"".format(item, output))
            else:
                print("\"{}\" is not present in \"{}\"".format(item, output))
                return 0
        return 1
    else:
        big_str = "\n".join(output)
        print("in list")
        if type(value) is str:
            if value in output:
                print("\"{}\" is present in \"{}\"".format(value, output))
                return 1
            else:
                print("\"{}\" is not present in \"{}\"".format(value, output))
                return 0
        for item in value:
            if re.search(item, big_str, re.I):
                print("\"{}\" is present in \"{}\"".format(item, output))
            else:
                print("\"{}\" is not present in \"{}\"".format(item, output))
                return 0
        return 1


def not_in_fun(output, value, index=None):
    if type(output) is str:
        if type(value) is str:
            if value in output:
                print("\"{}\" is present in \"{}\"".format(value, output))
                return 0
            else:
                print("\"{}\" is not present in \"{}\"".format(value, output))
                return 1
        for item in value:
            if re.search(item, output, re.I):
                print("\"{}\" is present in \"{}\"".format(item, output))
            else:
                print("\"{}\" is not present in \"{}\"".format(item, output))
                return 1
        return 0
    else:
        big_str = "\n".join(output)
        print("in list")
        if type(value) is str:
            if value in output:
                print("\"{}\" is present in \"{}\"".format(value, output))
                return 0
            else:
                print("\"{}\" is not present in \"{}\"".format(value, output))
                return 1
        for item in value:
            if re.search(item, big_str, re.I):
                print("\"{}\" is present in \"{}\"".format(item, output))
            else:
                print("\"{}\" is not present in \"{}\"".format(item, output))
                return 1
        return 0


def equal(output, value, index=None):
    if index is None:
        status = int(str(output) == str(value))
        if status:
            print("{0} is equal to {1}".format(output, value))
        else:
            print("{0} is not equal to {1}".format(output, value))
        return status
    else:
        index = int(index)
        try:
            status = int(float(output[index]) == float(value))
            if status:
                print("{0} is equal to {1}".format(output[index], value))
            else:
                print("{0} is not equal to {1}".format(output[index], value))
            return status
        except ValueError:
            status = int(str(output[index]) == str(value))
            if status:
                print("{0} is equal to {1}".format(output[index], value))
            else:
                print("{0} is not equal to {1}".format(output[index], value))
            return status


def nequal(output, value, index):
    if index is None:
        return int(float(output) != float(value))
    else:
        return int(float(output[int(index)]) != float(value))


def grt_than(output, value, index):
    print("index:", index)
    print("output:", output)
    print("value:", value)
    if index is None:
        if type(output) is list:
            for item in output:
                if float(item) > float(value):
                    continue
                else:
                    return 0
            return 1
        status = int(float(output) > float(value))
        if status:
            print("{0} is greater than {1}".format(output, value))
        else:
            print("{0} is not greater than {1}".format(output, value))
        return status
    else:
        index = int(index)
        status = int(float(output[index]) >= float(value))
        if status:
            print("{0} is greater than {1}".format(output[index], value))
        else:
            print("{0} is not greater than {1}".format(output[index], value))
        return status


def grt_thaneq(output, value, index):
    if index is None:
        return int(float(output) >= float(value))
    else:
        return int(float(output[int(index)]) == float(value))


def ls_than(output, value, index):
    if index is None:
        if type(output) is list:
            for item in output:
                if float(item) < float(value):
                    continue
                else:
                    return 0
            return 1
        status = int(float(output) < float(value))
        if status:
            print("{0} is less than {1}".format(output, value))
        else:
            print("{0} is not less than {1}".format(output, value))
        return status
    else:
        index = int(index)
        status = int(float(output[index]) < float(value))
        if status:
            print("{0} is less than {1}".format(output[index], value))
        else:
            print("{0} is not less than {1}".format(output[index], value))
        return status


def ls_thaneq(output, value, index):
    if index is None:
        if type(output) is list:
            for item in output:
                if float(item) <= float(value):
                    continue
                else:
                    return 0
            return 1
        status = int(float(output) <= float(value))
        if status:
            print("{0} is less than {1}".format(output, value))
        else:
            print("{0} is not less than {1}".format(output, value))
        return status
    else:
        index = int(index)
        status = int(float(output[index]) <= float(value))
        if status:
            print("{0} is less than {1}".format(output[index], value))
        else:
            print("{0} is not less than {1}".format(output[index], value))
        return status


def status_wrapper(flag):
    print("flag:", flag)
    status_ds = {
        "in": in_fun,
        "nin": not_in_fun,
        "eq": equal,
        "neq": nequal,
        "gt": grt_than,
        "gte": grt_thaneq,
        "lt": ls_than,
        "lte": ls_thaneq
    }
    return status_ds[flag]


def health_check_func(child, device):
    for dvc_id, var in libRSE.HEALTH_CHECK_DICT.items():
        print("Devices being used for the test case:")
        print(libRSE.HEALTH_CHECK_DICT.keys())
        print("checking connectivity of {}".format(dvc_id))
        if not var["connectivity"]:
            print("{} is not connected".format(dvc_id))
            print("Not filing the bug")
            return -1
        else:
            print("connected properly")
            print("Checking gps connectivity")
            if re.search("rsu", device, re.I):
                gps_status = libRSE.show_system_gpsstatus(
                    child, "show system gps status")
                if not re.search("NO FIX", gps_status):
                    print("GPS connected properly")
                else:
                    print("GPS is not connected. Not filing bug")
                    return -1
            else:
                gps_status = libRSE.obu_cgps(child, "obu cgps")
                if not re.search("NO FIX", gps_status):
                    print("GPS connected properly")
                else:
                    print("GPS is not connected. Not filing bug")
                    return -1

    # checking if multiple devices TX in same channel
    # if re.search("euobu", device, re.I):
    #    libRSE.euobu_gntool_getLocte(child, "obu gntool get_locte")


def jira_datastr_func():
    # This func returns required data to file bug Automatically as a form of string
    data_str = None
    tc_attributes = libRSE.TC_ATTRIBUTES_DICT
    if tc_attributes["jira_id"]:
        tc_attributes["description"] = re.sub(
            ",", " ", tc_attributes["description"])
        data_str = tc_attributes["project_id"].strip() + "," +\
            tc_attributes["issue_id"].strip() + "," +\
            tc_attributes["jira_id"].strip() + "," +\
            tc_attributes["description"].strip() + \
            "." + \
            tc_attributes["path to logs"].strip() + "," + "NA"
    return data_str


@logger_check_status
def check_status(output, value=1, flag="eq", index=None, device=None):
    testcase_id = libRSE.TESTCASE_ID  # testcase filename which contains the test id
    safe_fw_path = libRSE.config.SAFE_FW_PATH
    if re.search(r"^_[\w\d\s]+", str(value)):
        # This condition is used when passing varibles which are defined in config.py
        key = "{}".format(value[1:])
        print("key:", key)
        print("type:", type(key))
        value = config.scr_var[key]
    status = status_wrapper(flag.strip().lower())(output, value, index)
    if status == 0:
        print("Testcase failure")
        libRSE.end_of_testcase(test_result=False)
        global DEVICE  # it is the spawned child process to RSU/OBU/EUOBU
        child = DEVICE
        if re.search("obu", device, re.I):
            # Tear down is happening
            obu_reset_func(child, "obu reset")
        ret = health_check_func(child, device)
        # IF health check fails. Not filing bug.
        if ret == -1:
            return status
        genLib.file_backup_func(child, device, testcase_id)
        os.chdir("{}/".format(safe_fw_path))
        data_str = jira_datastr_func()
        if not data_str:
            print("Got Jira ID as None.")
            print("Not filing the bug. Need to rise or update bug manually.")
            return status
        else:
            print("Filing bug. Calling JiraInvoker.")
            jira_invoker = "jython {0}/JiraInvoker.py {0} \"{1}\"".format(
                safe_fw_path, data_str)
            print(jira_invoker)
            # os.system(jira_invoker)
        print("Execution stops on failure")
    return status
