# -*- coding: utf-8 -*-
import re
import pandas as pd
import socket
import argparse
import os
import datetime
import pyshark
import config
import coc_config
from time import sleep
from subprocess import Popen
import csv
from pandas import DataFrame as df
import pexpect
import libRSE

STOP_FLAG_RX = 1
STOP_FLAG_TX = 2
iut_conn_dict = dict()

dev_status_data_dict = {
    "device": None,
    "tcid": None,
    "stop_cmd": None,
    "stop_flag": None,
    "file_name": None
}

coc_dev_state_dict = dict()

dev_set = list()

option_dict = {
    "hexcode": None,
    "file_name": None
}

global count

count = 1

_pcap_name = None


def str_to_bin(code):
    code = re.sub(r"(\s+)", "", code)
    byt_arr = bytearray()
    try:
        for byte in (code[j:j + 2] for j in range(0, len(code), 2)):
            byt_arr.append(int(byte, 16))
    except IndexError:
        print("End of code reached")
        return byt_arr
    return byt_arr


# child and cmd arguments are by default added by autoGen parser


def tshark_wrapper(child, cmd, count=100, interface="wlp2s0", time=30):
    global _pcap_name
    timestamp = datetime.datetime.now().strftime("%b_%d_%I_%M_%S_%Y")
    _pcap_name = "{}_pcap".format(timestamp)
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    opt_dct = {
        "pkt_name": "{}/resource/coc/{}".format(safe_path, _pcap_name),
        "interface": interface,
        "time": "duration:{}".format(time),
        "capture_format": "pcap",
        "filter": "udp port 13001",
        "count": int(count)
    }
    command = "tshark:-i:{interface}:-f:{filter}:-c:{count}:-w:{pkt_name}".format(
        **opt_dct)
    print(command)
    cmd = command.split(":")
    print(cmd)
    Popen(cmd)
    sleep(3)
    # os.system(command)
    return 1


# def ota_pcap():
#    ota_dev_dtils = coc_config.ota_dev_dtils
#    return 1


def calc_psid_len(data):
    if int(data[0:2], 16) == 128:
        return 1
    elif int(data[2:4], 16) == 128:
        return 2
    elif int(data[4:6], 16) == 128:
        return 4
    elif data[0:6] == '818181':
        return int(data[6:8], 16)
    else:
        return -1


def parse_pcaps(pcap_file, psid):
    data_dict = {}
    packet = None
    for pkt in pcap_file:
        hex_resp = pkt.data.data
        if pkt.ip.proto != 17 and hex_resp[22:24] != '82':
            continue
        psid_len = calc_psid_len(hex_resp[36:]) * 2
        if psid_len == 8 and hex_resp[40:42] == "80":
            psid_base_index = 36 + (psid_len - 2)
        else:
            psid_base_index = 36 + psid_len
        # print(hex_resp[psid_base_index:psid_base_index+psid_len])
        if int(hex_resp[psid_base_index:psid_base_index + psid_len], 16) != int(psid):
            continue
        # data_dict[hex_resp]=pkt.sniff_timestamp
        # hex_resp=hex_resp[0:4]+hex_resp[20:50+psid_len]+hex_resp[50+psid_len+2:]
        hex_resp = hex_resp[0:4] + hex_resp[20:48 + psid_len + len(psid)] + hex_resp[48 + psid_len + len(psid) + 2:]
        data_dict[hex_resp] = float(pkt.sniff_timestamp)
        packet = pkt
    return packet, data_dict


def pcap_reader_verify_psid(child, cmd, psid1=None, psid2=None, option=None):
    global _pcap_name
    sleep(3)
    pcap_path = "{}/resource/coc/{}".format(config.SAFE_FW_PATH, _pcap_name)

    if psid1 is None:
        print("PSID not given")
        return -1
    try:
        pcap_file = pyshark.FileCapture(pcap_path)
    except FileNotFoundError:
        print("File didn't find:{}".format(pcap_path))
        return -1
    if psid1 and psid2 is not None:
        print(f"evaluating for alternate channel\n")
        print(f"evaluating for {psid1} PSID\n")
        packet, dict1 = parse_pcaps(pcap_file, psid1)
        print(dict1)
        print(f"evaluating for {psid2} PSID\n")
        packet, dict2 = parse_pcaps(pcap_file, psid2)
        print(dict2)
        if len(dict1) and len(dict1) == 1:
            print(f"for given {psid1} and {psid2} data is identical")
            return "1"
        else:
            print(f"for given {psid1} and {psid2} data is different")
            return "-1"
    else:
        print(f"evaluating for continous channel \n")
        print(f"evaluating for {psid1} channel\n")
        packet, dict1 = parse_pcaps(pcap_file, psid1)
        if len(dict1) == 1:
            print("All are identical data")
            hex_resp = packet.data.data
            hex_resp_len = len(hex_resp)
            hex_data = [hex_resp[i:i + 2] for i in range(0, hex_resp_len, 2)]
            return_dict = {"data": hex_data, "time": list(dict1.values())[0]}
            try:
                return return_dict[option]
            except KeyError:
                print(dict1)
                return "1"
        else:
            print("Data is different")
            print(dict1)
            return "-1"


def pcap_reader_csv_save(child, cmd, psid1=None, testid=""):
    global _pcap_name
    sleep(3)
    time_stamp_list = []
    pcap_path = "{}/resource/coc/{}".format(config.SAFE_FW_PATH, _pcap_name)

    if psid1 is None:
        print("PSID not given")
        return -1

    try:
        pcap_file = pyshark.FileCapture(pcap_path)
    except FileNotFoundError:
        print("File didn't find:{}".format(pcap_path))
        return -1

    for pkt in pcap_file:

        hex_resp = pkt.data.data

        if pkt.ip.proto != 17 and hex_resp[22:24] != '82':
            continue

        psid_len = calc_psid_len(hex_resp[36:]) * 2
        psid_base_index = 36 + psid_len
        # print(hex_resp[psid_base_index:psid_base_index+psid_len])

        if hex_resp[psid_base_index:psid_base_index + psid_len] != psid1:
            continue
        time_stamp_list.append(pkt.sniff_timestamp)
    pd1 = pd.DataFrame({"Time": time_stamp_list})
    filename = f"{config.SAFE_FW_PATH}/resource/coc/tcpdump_pcaps/ind_{testid}_{psid1}.csv"
    pd1.to_csv(filename, index=False)
    return filename


def pcap_reader(child, cmd, tx_rx, option, ota=False):
    # if ota:
    #    ota_pcap()
    global _pcap_name
    # _pcap_name="Nov_30_12_00_04_2018_pcap"
    sleep(3)
    # rx2 for get ipv6 and
    pkt_type = {"tx": '80', "rx": '81', "rx2": '83'}
    pcap_path = "{}/resource/coc/{}".format(config.SAFE_FW_PATH, _pcap_name)
    try:
        pcap_file = pyshark.FileCapture(pcap_path)
    except FileNotFoundError:
        print("File didn't find:{}".format(pcap_path))
        return -1
    out_pkt = None
    count = 0
    for pkt in pcap_file:
        try:
            hex_resp = pkt.data.data
        except AttributeError:
            continue
        hex_resp_len = len(hex_resp)
        hex_data = [hex_resp[i:i + 2] for i in range(0, hex_resp_len, 2)]
        if hex_data[11] == pkt_type[tx_rx]:
            out_pkt = pkt
            print(count)
            break
        else:
            count = count + 1
            continue

    if out_pkt:
        pkt_data_dict = {
            "timestamp": float(pkt.sniff_timestamp),
            "data": hex_data}
        try:
            return pkt_data_dict[option]
        except KeyError:
            print("Didn't find the option:{}".format(option))
            return -1

    # pkt = pcap_file[pkt_type[tx_rx]]
    # hex_resp = pkt.data.data
    # hex_resp_len = len(hex_resp)
    # hex_data = [hex_resp[i:i + 2] for i in range(0, hex_resp_len, 2)]
    # pkt = pcap_file[pkt_type[tx_rx]]
    # pkt_data_dict = {
    #     "timestamp": float(pkt.sniff_timestamp),
    #     "data": hex_data}
    # try:
    #     return pkt_data_dict[option]
    # except KeyError:
    #     print("Didn't find the option:{}".format(option))
    #     return -1


def obu_coc_copy(child, file_name, copy_name):
    "Author: Manasa Dosapati"
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    child.sendline("")
    child.expect(config.OBUPMT)
    print(file_name)
    command = "scp {0} {1}@{2}:{3}/resource/coc/tcpdump_pcaps/{4}".format(
        file_name, config.SYS_UNAME, config.SYS_HOST, safe_path, copy_name)
    print(command)
    print("PMT:", config.OBUPMT)
    child.sendline(command)
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        print(child.before)
        child.expect(config.OBUPMT)
        return 1
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        return 1


def coc_copy(child, file_name, copy_name):
    "Author: Manasa Dosapati"
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    child.sendline("")
    child.expect(config.SHELLPMT)
    print(file_name)
    command = "scp {0} {1}@{2}:{3}/resource/coc/tcpdump_pcaps/{4}".format(
        file_name, config.SYS_UNAME, config.SYS_HOST, safe_path, copy_name)
    print(command)
    child.sendline(command)
    sleep(2)
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.SHELLPMT)
        return 1
    except pexpect.TIMEOUT:
        print("TIMEOUT exception occured")
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.SHELLPMT)
        return 1


def get_coc_mac(child, cmd, *args):
    "Author: Manasa Dosapati"
    try:
        child.sendline("")
        child.expect(config.SHELLPMT)
        try:
            path = args[0]
            field = args[1]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field, "print", path)
        print(awk_cmd)
        child.sendline(awk_cmd)
        child.expect(config.SHELLPMT)
        awk_data = str(child.before, "utf-8")
        awk_data_str = re.split(r"\n", awk_data)
        conf_str = [line for line in awk_data_str if re.search(
            r"^{}".format(field), line)]
        print(conf_str)
        mac = re.search("(([\da-fA-F]){2}:?){6}", conf_str[0]).group()
        print(mac)
        return mac
    except IndexError:
        print("Please provide the valid argument to fetch")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in get_coc_mac function")
        return None


def obu_get_coc_mac(child, cmd, *args):
    "Author: Manasa Dosapati"
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field = args[1]
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field, "print", path)
        print(awk_cmd)
        child.sendline(awk_cmd)
        child.expect(config.OBUPMT)
        awk_data = str(child.before, "utf-8")
        awk_data_str = re.split(r"\n", awk_data)
        conf_str = [line for line in awk_data_str if re.search(
            r"^{}".format(field), line)]
        print(conf_str)
        mac = re.search("(([\da-fA-F]){2}:?){6}", conf_str[0]).group()
        print(mac)
        return mac
    except IndexError:
        print("Please provide the valid argument to fetch")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in get_coc_mac function")
        return None


def latest_pcap(child, cmd, *args, test_id2=None):
    "Author: Manasa Dosapati"
    try:
        filepath = args[0]
        test_id = args[1]
        print(len(args))
        child.sendline("")
        child.expect(config.SHELLPMT)
        abs_path = os.path.abspath(filepath)
        print(abs_path)
        child.sendline("cd {}".format(abs_path))
        child.expect(config.SHELLPMT)
        child.sendline("")
        child.expect(config.SHELLPMT)
        sys_cmd = "`ls -rt | tail -n 1`"
        latest_file = "ls -rt | tail -n 1"
        child.sendline(latest_file)
        child.expect(config.SHELLPMT)
        pcap_name = "{}.pcap".format(test_id)
        print(pcap_name)
        last_file = "ls -lrt"
        child.sendline(last_file)
        child.expect(config.SHELLPMT)
        print(last_file)
        print(child.before)
        coc_copy(child, sys_cmd, pcap_name)
        try:
            if len(args) > 2:
                test_id2 = args[2]
                child.sendline("")
                child.expect(config.SHELLPMT)
                abs_path = os.path.abspath(filepath)
                print(abs_path)
                child.sendline("cd {}".format(abs_path))
                child.expect(config.SHELLPMT)
                child.sendline("")
                child.expect(config.SHELLPMT)
                sys_cmd = "`ls -rt | tail -n 2 | head -n 1`"
                pcap_name = "{}.pcap".format(test_id2)
                print(pcap_name)
                child.sendline("ls -lrt")
                child.expect(config.SHELLPMT)
                last_file2 = "ls -lrt"
                child.sendline(last_file2)
                child.expect(config.SHELLPMT)
                print(last_file)
                print(child.before)
                coc_copy(child, sys_cmd, pcap_name)
                print("Executed test in alternating channel")
            else:
                print("This is a continuous test case")
        except IndexError:
            test_id2 = None
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None


def obu_latest_pcap(child, cmd, *args, test_id2=None):
    "Author: Manasa Dosapati"
    try:
        filepath = args[0]
        test_id = args[1]
        print(len(args))
        child.sendline("")
        child.expect(config.OBUPMT)
        abs_path = os.path.abspath(filepath)
        print(abs_path)
        child.sendline("cd {}".format(abs_path))
        child.expect(config.OBUPMT)
        child.sendline("")
        child.expect(config.OBUPMT)
        sys_cmd = "`ls -rt | tail -n 1`"
        latest_file = "ls -rt | tail -n 1"
        child.sendline(latest_file)
        print(latest_file)
        pcap_name = "{}.pcap".format(test_id)
        print(pcap_name)
        last_file = "ls -lrt"
        child.sendline(last_file)
        child.expect(config.OBUPMT)
        print(last_file)
        # print(child.before)
        print("\n**********************")
        output = str(child.before, "utf-8")
        print(output)
        print("\n**********************")
        obu_coc_copy(child, sys_cmd, pcap_name)
        try:
            if len(args) > 2:
                test_id2 = args[2]
                child.sendline("")
                child.expect(config.OBUPMT)
                abs_path = os.path.abspath(filepath)
                print(abs_path)
                child.sendline("cd {}".format(abs_path))
                child.expect(config.OBUPMT)
                child.sendline("")
                child.expect(config.OBUPMT)
                sys_cmd = "`ls -rt | tail -n 2 | head -n 1`"
                pcap_name = "{}.pcap".format(test_id2)
                print(pcap_name)
                last_file = "ls -lrt"
                child.sendline(last_file)
                child.expect(config.OBUPMT)
                print(last_file)
                # print(child.before)
                print("\n**********************")
                output = str(child.before, "utf-8")
                print(output)
                print("\n**********************")
                obu_coc_copy(child, sys_cmd, pcap_name)
                print("Executed test in alternating channel")
            else:
                print("This is a continuous test case")
        except IndexError:
            test_id2 = None
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None


def pcap_to_csv(child, cmd, test_id, mac, count):
    "Author: Manasa Dosapati"
    pcap_name = "{}.pcap".format(test_id)
    filtered_pcap_name = "{}_pcap.pcap".format(test_id)
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    pcap_path = "{0}/resource/coc/tcpdump_pcaps/".format(safe_path)
    command = "tshark,-r,{0}{1},-T,fields,-e,_ws.col.Time,-Y,wlan.sa=={2},>,tshark,-w,{3}{4}".format(
        pcap_path, pcap_name, mac, pcap_path, filtered_pcap_name)
    print(command)
    tshark_cmd = command.split(",")
    print(tshark_cmd)
    ts_cmd = " ".join(tshark_cmd)
    print(ts_cmd)
    os.system(ts_cmd)
    command2 = "tshark,-r,{0}{1},-T,fields,-e,_ws.col.Time,-Y,wlan.sa=={2},-c,{3},>,{4}{5}_csv.csv".format(
        pcap_path, filtered_pcap_name, mac, count, pcap_path, test_id)
    print(command2)
    tshark_cmd2 = command2.split(",")
    print(tshark_cmd2)
    ts_cmd2 = " ".join(tshark_cmd2)
    print(ts_cmd2)
    os.system(ts_cmd2)
    csv_file = "{}_csv.csv".format(test_id)
    df = pd.read_csv(f"{pcap_path}{csv_file}", header=None)
    df.columns = ["Time"]
    time_file = "{}_csv_time.csv".format(test_id)
    df.to_csv(f"{pcap_path}{time_file}")
    return time_file


# def pcap_to_csv_rx_case(child, cmd, test_id, mac, count, len_of_pkt):
#     "Author: Manasa Dosapati"
#     pcap_name = "{}.pcap".format(test_id)
#     safe_path = os.path.abspath(config.SAFE_FW_PATH)
#     pcap_path = "{0}/resource/coc/tcpdump_pcaps/".format(safe_path)
#     # command = "tshark,-r,{0}/{1},-T,fields,-e,_ws.col.Time,-Y,(wlan.sa=={2}&&frame.len=={3}),-c,{4},>,{5}/{6}_csv.csv".format(
#     #     pcap_path, pcap_name, mac, len_of_pkt, count, pcap_path, test_id)
#     command = 'tshark,-r,{0}/{1},-T,fields,-e,_ws.col.Time,-e,frame.len,-Y,"(wlan.sa=={2}&&frame.len=={3})",-c,{4},>,{5}/{6}_csv.csv'.format(
#         pcap_path, pcap_name, mac, len_of_pkt, count, pcap_path, test_id)
#
#     print(command)
#     tshark_cmd = command.split(",")
#     print(tshark_cmd)
#     ts_cmd = " ".join(tshark_cmd)
#     print(ts_cmd)
#     os.system(ts_cmd)
#     csv_file = "{}_csv.csv".format(test_id)
#     df = pd.read_csv(f"{pcap_path}/{csv_file}", header=None,sep="\t")
#     df.columns = ["Time", "length"]
#     time_file = "{}_csv_time.csv".format(test_id)
#     df.to_csv(f"{pcap_path}{time_file}")
#     return time_file

def pcap_to_csv_rx_case(child, cmd, test_id, mac, count, len_of_pkt):
    "Author: Manasa Dosapati"
    pcap_name = "{}.pcap".format(test_id)
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    pcap_path = "{0}/resource/coc/tcpdump_pcaps/".format(safe_path)
    filtered_pcap_name = "{}_pcap.pcap".format(test_id)
    command = 'tshark,-r,{0}{1},-T,fields,-e,_ws.col.Time,-Y,"(wlan.sa=={2}&&frame.len=={5})",>,tshark,-w,{3}{4}'.format(
        pcap_path, pcap_name, mac, pcap_path, filtered_pcap_name, len_of_pkt)
    print(command)
    tshark_cmd = command.split(",")
    print(tshark_cmd)
    ts_cmd = " ".join(tshark_cmd)
    print(ts_cmd)
    os.system(ts_cmd)
    command2 = 'tshark,-r,{0}/{1},-T,fields,-e,_ws.col.Time,-e,frame.len,-Y,"(wlan.sa=={2}&&frame.len=={3})",-c,{4},>,{5}/{6}_csv.csv'.format(
        pcap_path, filtered_pcap_name, mac, len_of_pkt, count, pcap_path, test_id)
    print(command2)
    tshark_cmd2 = command2.split(",")
    print(tshark_cmd2)
    ts_cmd2 = " ".join(tshark_cmd2)
    print(ts_cmd2)
    os.system(ts_cmd2)
    csv_file = "{}_csv.csv".format(test_id)
    df = pd.read_csv(f"{pcap_path}{csv_file}", header=None, sep="\t")
    df.columns = ["Time", "length"]
    time_file = "{}_csv_time.csv".format(test_id)
    df.to_csv(f"{pcap_path}{time_file}")
    return time_file


def std_dev_cal(child, cmd, rr, repeatperiod_tol, csv_file):
    "Author: Manasa Dosapati"
    abc = []
    b = 0
    diff = []
    safe_path = config.SAFE_FW_PATH
    csv_file = "{}/resource/coc/tcpdump_pcaps/{}".format(safe_path, csv_file)
    with open(csv_file) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            try:
                abc.append(float(row['Time']))
            except ValueError:
                abc.append(0)
    print(csvfile, file=open('/home/sairam/stnd_dev.csv', 'a'))
    sum_of_all_values = 0
    msgrcvcount = 1
    for i in range(0, len(abc)):
        if i == (len(abc) - 1):
            break
        elif (abc[i + 1] - abc[i]):
            b = abc[i + 1] - abc[i]
            # print (abc[i+1], '-', abc[i], '=', b)
            # print (b)   #list of values
            # if b > (0.055):
            # print (b)
            # print (abc[i+1], abc[i])
            diff.append(b)
            sum_of_all_values += b
        # msgrcvcount += 1
    msgrcvcount = sum(1 for row in abc)
    print("MsgRcvCount = ", msgrcvcount)
    print("sum_of_all_values = ", sum_of_all_values)
    avgrp = 0
    avgrp = sum_of_all_values / (msgrcvcount - 1)
    print("AvgRP = ", avgrp)
    # print (diff)  #prints as array
    var = 0
    sum1 = 0
    rpstd = 0
    var1 = 0
    for i in diff:
        # print (i)         #diff values
        var = i - avgrp
        var1 = var ** 2
        # print (var)
        # print (var1)
        sum1 += var1
    print("sum_of_(delta_tn - AvgRP)^2 = ", sum1)
    sq_of_RPStdDev = sum1 / (msgrcvcount - 1)
    print("(RPStdDev)^2 = ", sq_of_RPStdDev)
    rpstd = sq_of_RPStdDev ** (1 / 2.0)
    print("RPStdDev = ", rpstd)
    SEM = 0
    SEM = (rpstd) / ((msgrcvcount) ** (1 / 2.0))
    print("SEM = ", SEM)
    rpmup = 0
    rpmlo = 0
    rpmup = avgrp + (1.96 * SEM)
    rpmlo = avgrp - (1.96 * SEM)
    print("RPMup = ", rpmup, file=open('/home/sairam/stnd_dev.csv', 'a'))
    print("RPMlo = ", rpmlo, file=open('/home/sairam/stnd_dev.csv', 'a'))
    repeatrate = "{}".format(float(rr))
    print("Repeat_Rate =", repeatrate)
    repeatrate = float(repeatrate)
    repeatperiod = 1.0 / repeatrate
    repeatperiod = float(repeatperiod)
    print("Repeat_Period = ", repeatperiod)
    repeatperiod_tolerance = "{}".format(float(repeatperiod_tol))
    repeatperiod_tolerance = float(repeatperiod_tolerance)
    print("repeatperiod_tolerance = ", repeatperiod_tolerance)
    if repeatperiod <= rpmup <= repeatperiod + repeatperiod_tolerance:
        print("RPMup = success")
    elif rpmup > repeatperiod + repeatperiod_tolerance:
        print("RPMup = fail")
    else:
        print("RPMup = fail with unexpected value")
    if repeatperiod >= rpmlo >= repeatperiod - repeatperiod_tolerance:
        print("RPMlo = success")
    elif rpmlo < repeatperiod - repeatperiod_tolerance:
        print("RPMlo = fail")
    else:
        print("RPMlo = fail with unexpected value")
    print('end')
    print('')
    op = [rpmup, rpmlo]
    return op


# def set_flags_coc_dev_func(key, file_name, tcid, request):
#     global dev_set
#     global coc_dev_state_dict
#     dev_status_data_dict = dict()
#     flag = 0
#     # if not re.search(r"stop", request):
#     #     dev_set.add(key)
#     if re.search(r"start_[\w]+_[tr]x\d?", request, re.I):
#         flag = 1
#         dev_set.add(key)
#         stop_cmd = re.sub(r"start", r"stop", request)
#         print("STOP_CMD", stop_cmd)
#         dev_status_data_dict["tcid"] = tcid
#         dev_status_data_dict["stop_cmd"] = stop_cmd
#         dev_status_data_dict["stop_flag"] = 1
#         dev_status_data_dict["file_name"] = file_name
#     elif re.search(r"add_user_service", request, re.I):
#         flag = 1
#         dev_set.add(key)
#         stop_cmd = "del_user_service"
#         dev_status_data_dict["tcid"] = tcid
#         dev_status_data_dict["stop_cmd"] = stop_cmd
#         dev_status_data_dict["stop_flag"] = 1
#         dev_status_data_dict["file_name"] = file_name
#     if flag:
#         coc_dev_state_dict[key] = dev_status_data_dict
#     print(coc_dev_state_dict)
#     return

def set_flags_coc_dev_func(key, file_name, tcid, request):
    global dev_set
    global coc_dev_state_dict
    global count
    dev_status_data_dict = dict()
    flag = 0
    # if not re.search(r"stop", request):
    #     dev_set.add(key)

    if re.search(r"start_[\w]+_[tr]x\d?", request, re.I):
        flag = 1
        dev_set.append(key)
        stop_cmd = re.sub(r"start", r"stop", request)
        print("STOP_CMD", stop_cmd)
        dev_status_data_dict["device"] = key
        dev_status_data_dict["tcid"] = tcid
        dev_status_data_dict["stop_cmd"] = stop_cmd
        dev_status_data_dict["stop_flag"] = 1
        dev_status_data_dict["file_name"] = file_name
    elif re.search(r"add_user_service", request, re.I):
        flag = 1
        dev_set.append(key)
        stop_cmd = "del_user_service"
        dev_status_data_dict["device"] = key
        dev_status_data_dict["tcid"] = tcid
        dev_status_data_dict["stop_cmd"] = stop_cmd
        dev_status_data_dict["stop_flag"] = 1
        dev_status_data_dict["file_name"] = file_name
    if flag:
        coc_dev_state_dict[f"status_{count}"] = dev_status_data_dict
        count = count + 1
    print(coc_dev_state_dict)
    return

def child_close_coc(child, cmd, *args):
    global _logger_libRSE
    logger = _logger_libRSE
    try:
        device = args[0]
        print("DE:{}".format(device))
        if re.search("obu", device, re.I):
            print("closing obu without default state")
            child.close(force=True)
            logger.info("Closed connection for {}".format(device))
            return 1
        elif re.search("rsu", device, re.I):
            try:
                child.sendline("\r")
                child.expect(config.CLIPMT)
                child.close(force=True)
                logger.info("Closed connection for {}".format(device))
                return 1
            except pexpect.TIMEOUT:
                try:
                    child.expect(config.SHELLPMT)
                except pexpect.TIMEOUT:
                    print("Unable to reset the RSU")
                    print("Closing the connection")
                libRSE.exit_fun(child, cmd)
                child.close(force=True)
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



def coc_script(child, cmd, key, file_name, tcid, request):
    global coc_dev_state_dict
    global iut_conn_dict
    if key not in iut_conn_dict.keys():
        iut_conn_dict[key] = child
    print("REQUEST:", request)
    if re.search(r"stop_[\w]+_[tr]x\d?", request, re.I):
        for key1 in coc_dev_state_dict.keys():
            if coc_dev_state_dict[key1]['device'] == key and coc_dev_state_dict[key1]['stop_cmd'] == request:
                coc_dev_state_dict[key1]["stop_flag"] = 0

    elif re.search(r"del_user_service", request, re.I):
        for key1 in coc_dev_state_dict.keys():
            if coc_dev_state_dict[key1]['device'] == key and coc_dev_state_dict[key1]['stop_cmd'] == request:
                coc_dev_state_dict[key1]["stop_flag"] = 0

    if re.search(r"resource", file_name):
        safe_path = os.path.abspath(config.SAFE_FW_PATH)
        file_name = os.path.basename(file_name)
        file_name = "{}/resource/coc/{}".format(safe_path, file_name)
    hx_cmd_file = pd.read_csv(file_name)
    test_case_ids = list(hx_cmd_file["test_case_id"])
    try:
        index = test_case_ids.index(tcid)
    except ValueError:
        print("Cannot find the test case id:{}".format(tcid))
        return -1
    req_cmd = hx_cmd_file[request][index]
    set_flags_coc_dev_func(key, file_name, tcid, request)
    # we should get the hex cmds from csv file provided
    print("Request sent:", req_cmd)
    hexcode = str_to_bin(req_cmd)
    sock_dtils = coc_config.sock_dtils[key]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(sock_dtils)
    sock.sendto(hexcode, (sock_dtils["ip addr IUT"], sock_dtils["udp port"]))
    sock.close()
    return 1


# def set_devices_to_init_state():
#     # this func is being called in case of test case failure or exception
#     global dev_set
#     global coc_dev_state_dict
#     if not dev_set:
#         return
#     print(coc_dev_state_dict)
#     print("DS:", dev_set)
#     dev_set_list = list(dev_set)
#     print(list(dev_set_list))
#     for key in dev_set_list:
#         tcid = coc_dev_state_dict[key]["tcid"]
#         request = coc_dev_state_dict[key]["stop_cmd"]
#         flag = coc_dev_state_dict[key]["stop_flag"]
#         file_name = coc_dev_state_dict[key]["file_name"]
#         if flag:
#             print("coc clean up")
#             print("key:", key)
#             print(coc_dev_state_dict[key])
#             coc_script(
#                 None, None, key, file_name, tcid, request)
#     return

def set_devices_to_init_state():
    # this func is being called in case of test case failure or exception
    global dev_set
    global coc_dev_state_dict
    if not dev_set:
        return
    print(coc_dev_state_dict)
    print("DS:", coc_dev_state_dict.keys())
    # event_set_list = list()
    # print(list(dev_set_list))
    for key1 in coc_dev_state_dict.keys():
        tcid = coc_dev_state_dict[key1]["tcid"]
        request = coc_dev_state_dict[key1]["stop_cmd"]
        flag = coc_dev_state_dict[key1]["stop_flag"]
        file_name = coc_dev_state_dict[key1]["file_name"]
        if flag:
            print("coc clean up")
            print("key:", coc_dev_state_dict[key1]['device'])
            print(coc_dev_state_dict[key1]['device'])
            coc_script(
                None, None, coc_dev_state_dict[key1]['device'], file_name, tcid, request)
    return


def coc_killall(device):
    if not device:
        print("coc app is not killed")
        return -1
    global iut_conn_dict
    for key in iut_conn_dict.keys():
        if re.search("RSU", key):
            if re.search("RSUIUT1", key):
                continue
            child = iut_conn_dict[key]
            try:
                child.sendline("show system date")
                child.expect(config.CLIPMT)
                libRSE.direct_to_shell_mode(child, "cmd", device)
                print("D1:", child.before, child.after)
            except libRSE.pexpect.TIMEOUT:
                child.sendline("date")
                child.expect(config.SHELLPMT)
                # libRSE.direct_to_shell_mode(child, "cmd", device)
            child.sendline("killall coc_tcia")
            child.expect(config.SHELLPMT)
            print("D2:", child.before, child.after)
            child.sendline("exit")
            child.expect(config.CLIPMT)
            print("D3:", child.before, child.after)
        elif re.search("^OBUIUT", key):
            if re.search("OBUIUT1", key):
                continue
            child.sendline("killall coc_tcia")
            child.expect(config.OBUPMT)
    return


def main():
    sock_dtils = coc_config.sock_dtils
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if option_dict["hexcode"]:
        hexcode = str_to_bin(option_dict["hexcode"])
        sock.sendto(hexcode, (sock_dtils["ip_addr"], sock_dtils["port"]))
        data = sock.recv(2048)
        print("DATA", data[1:2])
        return 1
    return 1


## this func is wrapper around check_status in main.py
#
# def coc_check_status(output, value=1, flag="eq"):
#    global dev_set
#    global coc_dev_state_dict
#    status = main.check_status(output, value, flag)
#    dev_set_gen = (dev_set.pop() for _ in dev)
#    if not status:
#        for key in dev_set_gen:
#            tcid = coc_dev_state_dict[key]["tcid"]
#            request = coc_dev_state_dict[key]["request"]
#            flag = coc_dev_state_dict[key]["stop_flag"]
#            if flag:
#                coc_script(None, None, key, tcid, request)
#    return


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-x", "--hexcode",
                            help="hexcode to send as command")
    arg_parser.add_argument("-fn", "--file_name",
                            help="csv file_name to read and send commands")
    args = arg_parser.parse_args()
    option_dict["hexcode"] = args.hexcode
    option_dict["file_name"] = args.file_name
    main()
