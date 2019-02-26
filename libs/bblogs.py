import pandas as pd
import numpy as np
import config
import pexpect
import os
from time import sleep
import glob
import datetime
import re

global _BLACK_BOX_FILE_NAME
global _BLACK_BOX_FILE_NAME_FTR


def log_file_copy(child, path, last_modified=1):
    global _BLACK_BOX_FILE_NAME
    child.sendline("")
    child.expect(config.OBUPMT)
    child.sendline("cd /nojournal/bblogs/")
    child.expect(config.OBUPMT)
    scp_cmd = "scp `ls -rt | tail -n {0} | head -n 1` {1}@{2}:{3}/{4}".format(last_modified,
                                                                              config.SYS_UNAME, config.SYS_HOST,
                                                                              config.SAFE_FW_PATH, path)
    print(scp_cmd)
    child.sendline("ls -l")
    child.expect(config.OBUPMT)
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
    except pexpect.exceptions.TIMEOUT:
        print("blackbox log files not generated..Kindly verify EnableLogger flag")
        return
    # Changing to home directory after copying the black box log
    child.sendline("cd")
    child.expect(config.OBUPMT)

    os.chdir("{0}/resource/bblogs".format(config.SAFE_FW_PATH))

    bb_files = glob.glob("eebl_log_denm*")  # list all the files
    bb_files.extend(glob.glob("BlackBox**"))
    bb_files.extend(glob.glob("eu_*"))
    bb_file = max(bb_files, key=os.path.getctime)  # get the latest file name
    HOME = os.getenv("HOME")
    _BLACK_BOX_FILE_NAME = bb_file
    copy = "cp {} {}/SAFElogs/{}".format(bb_file,
                                         HOME,
                                         _BLACK_BOX_FILE_NAME)

    print("Black Box:{}".format(bb_file))
    print(copy)
    os.system(copy)


def filter_api(child, cmd, *args):
    global _BLACK_BOX_FILE_NAME_FTR
    global _BLACK_BOX_FILE_NAME

    if len(args) % 2 != 0:
        modified_flag = args[-1]
        log_file_copy(child, "resource/bblogs/", modified_flag)
        args = args[:-1]
    else:
        log_file_copy(child, "resource/bblogs/")
    bb_file = _BLACK_BOX_FILE_NAME
    bb_log = pd.read_csv(bb_file)
    num_args = len(args) // 2
    print(num_args)
    for key, val in zip(args[:num_args], args[num_args:]):
        val = val.strip("\"")
        bb_log = bb_log[bb_log[key] == val]
    bb_len = bb_log.shape[0]
    ind = np.arange(bb_len)
    bb_log.index = ind
    _BLACK_BOX_FILE_NAME_FTR = "black_box_file.csv"
    bb_log.to_csv(
        "{0}/resource/bblogs/{1}".format(config.SAFE_FW_PATH,
                                         _BLACK_BOX_FILE_NAME_FTR))
    return 1


def bb_log_field_specific_api(child, cmd, *args):
    global _BLACK_BOX_FILE_NAME_FTR
    if len(args) > 0:
        field = args[0].strip()
        try:
            val_list = args[1:]
        except IndexError:
            val_list = None
        os.chdir("{0}/resource/bblogs".format(config.SAFE_FW_PATH))
        blackbox_file = pd.read_csv(_BLACK_BOX_FILE_NAME_FTR)
        field_to_api = {
            "fcwState": fcwState,
            "imaState": imaState,
            "BSAState": bsaState,
            "eeblState": eeblState,
        }
        return field_to_api[field](blackbox_file, *val_list)
    else:
        print("Provide label in CSV file to be verified")
        return -1


def fcwState(bb_file, *args):
    global _BLACK_BOX_FILE_NAME
    try:
        fcw_state_imminent_max = float(args[0])
        fcw_state_advisory_max = float(args[1])
        fcw_state_info_max = float(args[2])
    except IndexError:
        print("Provide valid number of arguments")
        return -1

    fcwState_data = bb_file.loc[:, "fcwState"]
    TtcSec_data = bb_file.loc[:, "TtcSec"]
    failed_list = []
    for index, value in enumerate(TtcSec_data):
        if 0.0 <= float(value) <= fcw_state_imminent_max and fcwState_data[
            index] == "FCW_IMMINENT":
            continue
        elif fcw_state_imminent_max <= float(value) <= fcw_state_advisory_max and \
                fcwState_data[index] == "FCW_ADVISORY":
            continue
        elif fcw_state_advisory_max <= float(value) <= fcw_state_info_max and \
                fcwState_data[index] == "FCW_INFO":
            continue
        elif float(value) > fcw_state_info_max and fcwState_data[index] == "FCW_CLEAR":
            continue
        elif np.isnan(TtcSec_data[index]):
            break
        else:
            failed_list.append(index + 1)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"fcwState is invalid for multiple rows ")
        print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
        return "-1"
    print(f"fcwState is valid for multiple rows")
    print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
    return 1


def imaState(bb_file, *args):
    global _BLACK_BOX_FILE_NAME
    try:
        type_of_application = str(args[0].split("IMA")[0]).upper()
        ima_state_imminent_max = float(args[1])
        ima_state_advisory_max = float(args[2])
        ima_state_info_max = float(args[3])
    except IndexError:
        print("Provide valid number of arguments")
        return -1
    except ValueError:
        print("Provide valid number of arguments")
        return -1
    imaState_data = bb_file.loc[:, "imaState"]
    TtcSec_data = bb_file.loc[:, "TtcSec"]
    failed_list = []
    for index, value in enumerate(TtcSec_data):

        if 0.0 <= float(value) <= ima_state_imminent_max and imaState_data[
            index] == f"IMA_{type_of_application}_IMMINENT":
            continue
        elif ima_state_imminent_max <= float(value) <= ima_state_advisory_max and \
                imaState_data[index] == f"IMA_{type_of_application}_ADVISORY":
            continue
        elif ima_state_advisory_max <= float(value) <= ima_state_info_max and \
                imaState_data[index] == f"IMA_{type_of_application}_INFO":
            continue
        elif float(value) > ima_state_info_max and imaState_data[index] == "IMA_CLEAR":
            continue
        elif np.isnan(TtcSec_data[index]):
            break
        elif not re.search(type_of_application, imaState_data[index]):
            failed_list.append(index + 1)
            continue
        else:
            failed_list.append(index + 1)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"imaState is invalid for multiple rows ")
        print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
        return "-1"
    print(f"imaState is valid for multiple rows")
    print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
    return 1


def bsaState(bb_file, *args):
    global _BLACK_BOX_FILE_NAME
    try:
        type_of_application = str(args[0].split("BSA")[0])
        bsa_State_StartEdge_mts = float(args[1])
        bsa_State_StopEdge_mts = float(args[2])
    except IndexError:
        print("Provide valid number of arguments")
        return -1
    except ValueError:
        print("Provide valid number of arguments")
        return -1
    bsaState_data = bb_file.loc[:, "BSAState"]
    RV_Dc_data = bb_file.loc[:, "Rv_Dc"]
    failed_list = []
    for index, value in enumerate(bsaState_data):
        if value == f"{type_of_application}Advisory":
            if bsa_State_StartEdge_mts <= abs(float(RV_Dc_data[index])) <= bsa_State_StopEdge_mts:
                continue
            else:
                failed_list.append(index + 1)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"bsaState is invalid for multiple rows ")
        print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
        return "-1"
    print(f"bsaState is valid for multiple rows")
    print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
    return 1


def eeblState(bb_file, *args):
    global _BLACK_BOX_FILE_NAME
    try:
        eebl_acceleration_verify_val = args[0]
    except IndexError:
        # Providing hard coded value for WAVE stack
        eebl_acceleration_verify_val = -4
    except ValueError:
        print("Provide valid number of arguments")
        return -1
    eeblState_data = bb_file.loc[:, "eeblState"]
    RV_Acceleration_data = bb_file.loc[:, "RVAcceleration"]
    failed_list = []
    for index, value in enumerate(eeblState_data):
        if value == f"EEBL_IMMINENT":
            if RV_Acceleration_data[index] < eebl_acceleration_verify_val:
                continue
            else:
                failed_list.append(index + 1)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"eeblState is invalid for multiple rows ")
        print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
        return "-1"
    print(f"eeblState is valid for multiple rows")
    print("For manual verification refer:{}".format(_BLACK_BOX_FILE_NAME))
    return 1

def bb_log_get_value(child, cmd, label, index, values=None, *args):
    global _BLACK_BOX_FILE_NAME_FTR
    os.chdir("{0}/resource/bblogs".format(config.SAFE_FW_PATH))
    index = int(index)
    bb_file = pd.read_csv(_BLACK_BOX_FILE_NAME_FTR)
    label = label.strip()
    label = label.strip("\"")
    label_values = list(bb_file[label])
    value = label_values[index]
    return value
