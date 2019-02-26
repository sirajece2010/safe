import re
import pexpect
import sys
import os
import config
import libRSE
from time import sleep
import logging

_HEXDUMP = None
_HOME = os.getenv("HOME")

_logger_libRSE = logging
_file_handler_libRSE = None
_counter = None


def env_setup():
    global _HOME
    _HOME = os.getenv("HOME")
    if not os.path.exists("{}/SAFElogs".format(_HOME)):
        os.mkdir("{}/SAFElogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/bsmlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/bsmlogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/nojournal/".format(_HOME)):
            os.mkdir("{}/SAFElogs/nojournal/".format(_HOME))
    else:
        if not os.path.exists("{}/SAFElogs/bsmlogs".format(_HOME)):
            os.mkdir("{}/SAFElogs/bsmlogs".format(_HOME))
        if not os.path.exists("{}/SAFElogs/nojournal/".format(_HOME)):
            os.mkdir("{}/SAFElogs/nojournal/".format(_HOME))
    return 1


def get_latency_average(child, cmd, *args):
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
    libRSE.obu_scp(child, "obu scp", file_name, dest_path)
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


def convert_time_secs(child, cmd, time_string):
    if re.search("-", time_string):
        time_string = time_string.split("-")[1].split(":")
    else:
        time_string = time_string.split(":")
    if time_string[0] == '00':
        time_string[0] = 24
    return sum(x * int(t) for x, t in zip([3600, 60, 1], time_string))


def get_timestamp_from_file(child, cmd, *args, index_to_change=1):

    if len(args) >= 1:
        try:
            file_name = args[0]
        except IndexError:
            return "Provide required params"
    else:
        return "provide params"
    if index_to_change > 1:
        index_to_change -= 1
    child.sendline("")
    child.expect(config.OBUPMT)
    path = os.path.abspath(config.SAFE_FW_PATH)
    file_path = "{0}/resource/files".format(path)
    file_name = os.path.basename(file_name)
    print("FILE_NAME:{}".format(file_name))
    with open("{}/{}".format(file_path, file_name), 'r') as f:
        test_string = f.read()

    time_list = re.findall(r"([\d]{2}:[\d]{2}:[\d]{2})", test_string)

    try:
        return time_list[index_to_change]
    except IndexError:
        print("Provide valid index to find")


def verify_IG_BIT(child,cmd,count=1):

    try:
        for i in range(int(count)+1):
            libRSE.euobu_halt_run(child,"obu eu_halt")
            libRSE.euobu_halt_run(child, "obu eu_run")
            Mac_address = libRSE.euobu_tcpdump(child,"obu eutcpdump","ath1","OUT")
            if Mac_address:
                MSB=Mac_address.split(":")[0]
                lsb=int(MSB,16) & 128
                if int(lsb)==1:
                    print(f"IG Bit is set({lsb}) for {Mac_address} ")
                    return -1
                else:
                    print(f"IG Bit is not set({lsb}) for {Mac_address}")
        return 1
    except pexpect.TIMEOUT:
        print("Timeout happened in verify IG bit function")
        return None

