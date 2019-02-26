'''
    File name: libRSE.py
    Author: Ravi Teja Nagamothu
    Date created: 1/03/2018
    Python Version: 3.6
'''

import pandas as pd
import numpy as np
import config
import pexpect
import os
from time import sleep
import glob
import datetime
import re
_BSM_FILE_NAME = None
_BSM_FILE_NAME_FTR = None
_logger_bsm = None

def log_file_copy(child, path,last_modified=1):
    global _BSM_FILE_NAME
    child.sendline("")
    child.expect(config.OBUPMT)
    if re.search(r"EU", config.OBUPMT, re.I):
        child.sendline("cd /nojournal/cam_logs")
    else:
        child.sendline("cd /nojournal/bsmlogs")
    child.expect(config.OBUPMT)

    scp_cmd = "scp `ls -rt | tail -n {0} | head -n 1` {1}@{2}:{3}/{4}".format(last_modified,
        config.SYS_UNAME, config.SYS_HOST, config.SAFE_FW_PATH, path)
    print(scp_cmd)
    child.sendline(scp_cmd)
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        sleep(4)
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT)
        sleep(4)
    # Changing to home directory after copying the bsm_log
    child.sendline("cd")
    child.expect(config.OBUPMT)
    
    os.chdir("{0}/resource/bsmlogs".format(config.SAFE_FW_PATH))
    if re.search(r"EU", config.OBUPMT, re.I):
        bsm_files = glob.glob("CAService*") # list all the files
    else:
        bsm_files = glob.glob("inter*")  # list all the files
    bsm_file = max(bsm_files, key=os.path.getctime)  # get the latest file name
    HOME = os.getenv("HOME")
    _BSM_FILE_NAME = bsm_file
    copy = "cp {} {}/SAFElogs/bsmlogs/{}".format(bsm_file,
                                                 HOME,
                                                 _BSM_FILE_NAME)

    print("BSM:{}".format(bsm_file))
    print(copy)
    os.system(copy)


def timestamp():
    timestamp = datetime.datetime.now()
    date = str(timestamp.date())
    time = str(timestamp.time())
    timestamp = "{}_{}".format(date, time)
    return timestamp


def bsm_log_get_index(child, cmd, certchng=None, fieldkw=None):
    global _BSM_FILE_NAME
    global _BSM_FILE_NAME_FTR
    if certchng:
        certchng = certchng.strip("\"")
    bsm_log = pd.read_csv(_BSM_FILE_NAME_FTR)
    if fieldkw:
        return bsm_field_specific_api(bsm_log, fieldkw)
    cert = bsm_log["CertDigest"]
    if certchng == "digest":
        ind = cert[cert.isnull()].index
        ind = list(ind)
        return ind
    else:
        return cert_change(cert)


def filter_api(child, cmd, *args):
    global _BSM_FILE_NAME
    global _BSM_FILE_NAME_FTR

    if len(args) % 2 != 0:
        modified_flag = args[-1]
        log_file_copy(child, "resource/bsmlogs/", modified_flag)
        args = args[:-1]
    else:
        log_file_copy(child, "resource/bsmlogs/")
    bsm_file = _BSM_FILE_NAME
    bsm_log = pd.read_csv(bsm_file)
    num_args = len(args) // 2
    print(num_args)
    for key, val in zip(args[:num_args], args[num_args:]):
        val = val.strip("\"")
        bsm_log = bsm_log[bsm_log[key] == val]
    bsm_len = bsm_log.shape[0]
    ind = np.arange(bsm_len)
    bsm_log.index = ind
    _BSM_FILE_NAME_FTR = "bsm_file.csv"
    bsm_log.to_csv(
        "{0}/resource/bsmlogs/{1}".format(config.SAFE_FW_PATH,
                                          _BSM_FILE_NAME_FTR))
    return 1


def msg_cnt(bsm_log, *args):
    global _BSM_FILE_NAME
    # msgCnt = bsm_log.loc[:, "msgCnt"]  # ignoring the first packet
    msgCnt = bsm_log["msgCnt"]
    msg_len = len(msgCnt)
    timestamp = bsm_log["TimeStamp_ms"]
    msec = 5 * 60 * 100  # for 5 minutes
    msg_cond = [msgCnt[i + 1] - msgCnt[i] for i in range(msg_len - 1)]
    for ind, val in enumerate(msg_cond):
        if val != 1:
            if msgCnt[ind] == 127 and msgCnt[ind + 1] == 0:
                continue
            elif timestamp[ind] - timestamp[0] > msec - 10 and \
                    timestamp[ind] - timestamp[0] < msec + 10:
                continue
            else:
                print("MsgCnt not incrementing properly")
                print("Refer bsm log:{}".format(_BSM_FILE_NAME))
                print("Issue found at the index:{}".format(ind))
                return "-1"
    print("MsgCnt is in proper form")
    return 1


def sec_mark(bsm_log, *args):
    global _BSM_FILE_NAME
    secMark = bsm_log.loc[1:, "secMark"]  # ignoring the first packet
    # secMark = bsm_log["secMark"]
    secMark_cond = [val2-val1 for val1,val2 in zip(secMark[:-1], secMark[1:])]
    #print(secMark_cond)
    for ind, val in enumerate(secMark_cond):
        if val != 100:
            if secMark[ind+1] == 59900 and secMark[ind + 2] == 0:
                continue
            else:
                print("secMark not incrementing properly")
                print("Refer bsm log:{}".format(_BSM_FILE_NAME))
                print("Issue found at the index:{}".format(ind))
                return "-1"
    print("secMark is in proper form")
    return 1


def tx_interval(bsm_log, intv):
    global _BSM_FILE_NAME
    try:
        if not intv:
            print("Please provide the Tx_interval as configured")
        intv = int(intv)
        tx_intv = bsm_log.loc[1:, "TimeStamp_ms"]  # Ignoring the first row
        tx_intv_pairs = zip(tx_intv[0:], tx_intv[1:])
        iteration = 0
        failure_rows = list()
        for tx1, tx2 in tx_intv_pairs:
            diff = tx2 - tx1
            iteration += 1
            if diff >= intv - 10 and diff <= intv + 10:
                pass
            else:
                failure_rows.append(iteration)
        if failure_rows:
            print("Failure occurred at:{}".format(failure_rows))
            print("Tx interval not according to configured value")
            print("For manual verification refer:{}".format(_BSM_FILE_NAME))
            return "-1"
        print("BSM's are transmitted as per configuration Tx Interval")
        print("For manual verification refer:{}".format(_BSM_FILE_NAME))
        return 1
    except IndexError:
        print("Please provide the Tx_interval as configured")
        return "-1"


def v2vi_conf_val_chk(bsm_log, fieldkw=None):

    return


def bsm_field_specific_api(bsm_log, fieldkw):
    label = re.split(r"\d+", fieldkw)[0].strip()
    val = re.search(r"(\d+)", fieldkw)
    try:
        val = val.group(1)
    except AttributeError:
        val = None
    field_to_api = {
        "msgCnt": msg_cnt,
        "TxInterval": tx_interval,
        "secMark": sec_mark
    }
    return field_to_api[label](bsm_log, val)


def cert_change(cert):
    # cert is pandas.series type
    # removing null values
    cert_without_nan = cert[~cert.isnull()]
    unq = cert_without_nan.unique()  # listing unique values
    cert_list = list(cert)
    ind = [cert_list.index(val) for val in unq]
    ind[0] = 1 if ind[0] == 0 else print
    return ind


def bsm_log_get_value(child, cmd, label, index, values=None, *args):
    global _BSM_FILE_NAME_FTR
    os.chdir("{0}/resource/bsmlogs".format(config.SAFE_FW_PATH))
    index = int(index)
    bsm_file = pd.read_csv(_BSM_FILE_NAME_FTR)
    label = label.strip()
    label = label.strip("\"")
    label_values = list(bsm_file[label])
    try:
        value = label_values[index]
    except IndexError:
        value = 'None'
    return value
