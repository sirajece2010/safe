import pandas as pd
import numpy as np
import config
import pexpect
import os
from time import sleep
import glob
import datetime
import re

global _CAM_FILE_NAME
global _CAM_FILE_NAME_FTR


def log_file_copy(child, path, last_modified=1):

    global _CAM_FILE_NAME
    child.sendline("")
    child.expect(config.OBUPMT)
    if re.search(r"EU", config.OBUPMT, re.I):
        child.sendline("cd /nojournal/cam_logs")
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
        print("CAM log files not generated..Kindly verify CALogPath flag  and LogEnabled in CAService.conf")
        return
    # Changing to home directory after copying the cam_log
    child.sendline("cd")
    child.expect(config.OBUPMT)

    os.chdir("{0}/resource/camlogs".format(config.SAFE_FW_PATH))
    if re.search(r"EU", config.OBUPMT, re.I):
        cam_files = glob.glob("CAService*")  # list all the files
    cam_file = max(cam_files, key=os.path.getctime)  # get the latest file name
    HOME = os.getenv("HOME")
    _CAM_FILE_NAME = cam_file
    copy = "cp {} {}/SAFElogs/camlogs/{}".format(cam_file,
                                                 HOME,
                                                 _CAM_FILE_NAME)

    print("CAM:{}".format(cam_file))
    print(copy)
    os.system(copy)


def filter_api(child, cmd, *args, file_name=None):
    global _CAM_FILE_NAME
    global _CAM_FILE_NAME_FTR

    if len(args) % 2 != 0:
        modified_flag = args[-1]
        log_file_copy(child, "resource/camlogs/", modified_flag)
        args = args[:-1]
    else:
        log_file_copy(child, "resource/camlogs/")
    cam_file = _CAM_FILE_NAME
    cam_log = pd.read_csv(cam_file)
    num_args = len(args) // 2
    print(num_args)
    for key, val in zip(args[:num_args], args[num_args:]):
        val = val.strip("\"")
        cam_log = cam_log[cam_log[key] == val]
    cam_len = cam_log.shape[0]
    ind = np.arange(cam_len)
    cam_log.index = ind
    if file_name:
        _CAM_FILE_NAME_FTR = file_name
    else:
        _CAM_FILE_NAME_FTR = "cam_file.csv"
    cam_log.to_csv(
        "{0}/resource/camlogs/{1}".format(config.SAFE_FW_PATH,
                                          _CAM_FILE_NAME_FTR))
    return 1


def csv_file_comparison(child, cmd, *args):
    # TODO: ONLY works for pre-record. Need to support live mode.
    float_lookup = {
        "StationLatitude": 8,
        "StationLongitude": 8,
        "StationElevation": 8,
        "SemiMajorOrientation": 3,
        "HeadingValue": 4,
        "SpeedValue": 4,
        "VehicleLengthValue": 4,
        "VehicleWidth": 4,
        "LongAccelValue": 4,
        "YawRateValue": 3,
        "StrWhlAngleValue": 3,
        "LatAccelValue": 7,
        "VertAccelValue": 7
    }
    global _CAM_FILE_NAME_FTR
    try:
        validate_file = args[0]
    except:
        print("Provide required arguments")
        return -1

    src_file_path = f"{config.SAFE_FW_PATH}/resource/camlogs/{_CAM_FILE_NAME_FTR}"
    src_file = pd.read_csv(src_file_path)
    dest_file = pd.read_csv(f"{config.SAFE_FW_PATH}/{validate_file}")

    def remove_columns(target_file):
        for index, column_name in enumerate(target_file):
            if column_name == "StationType":
                target_file = target_file.iloc[:, index:]
                break
        return target_file

    src_file = remove_columns(src_file)
    dest_file = remove_columns(dest_file)
    return_str = ""
    column_list = []
    try:
        if args[1]:
            column_list = list(args[1:])
    except:
        column_list = list(src_file.iloc[:])

    for column in column_list:
        # print(f"Verifying column {column}\n")
        list1 = list(src_file[column])
        list2 = list(dest_file[column])
        for index in range(len(list2)):
            if str(list1[index]) == str(list2[index]) == 'nan':
                continue
            if column in list(float_lookup.keys()):
                if round(float(list1[index]), float_lookup[column]) != round(float(list2[index]), float_lookup[column]):
                    return_str += f"Both CSV's are different for column {column} at index {index+1}\n"\
                                  f"i.e. {list1[index]} ------------------> {list2[index]}\n"
                continue
            if float(list1[index]) != float(list2[index]):
                return_str += f"Both CSV's are different for column {column} at index {index+1}\n" \
                              f"i.e. {list1[index]} ------------------> {list2[index]}\n"

                continue

    if return_str:
        print(return_str)
        HOME = os.getenv("HOME")
        copy = "cp {} {}/SAFElogs/Failed_{}".format(src_file_path,
                                                    HOME,
                                                    os.path.basename(validate_file))
        print(copy)
        os.system(copy)
        return -1
    else:
        return 1


def cam_log_get_value(child, cmd, label, index, values=None, *args):
    global _CAM_FILE_NAME_FTR
    os.chdir("{0}/resource/camlogs".format(config.SAFE_FW_PATH))
    index = int(index)
    cam_file = pd.read_csv(_CAM_FILE_NAME_FTR)
    label = label.strip()
    label = label.strip("\"")
    label_values = list(cam_file[label])
    value = label_values[index]
    return value


def cam_field_specific_api(child, cmd, *args):
    global _CAM_FILE_NAME_FTR
    if len(args) > 0:
        field = args[0].strip()
        try:
            val = args[1]
        except IndexError:
            val = None
        os.chdir("{0}/resource/camlogs".format(config.SAFE_FW_PATH))
        cam_file = pd.read_csv(_CAM_FILE_NAME_FTR)
        field_to_api = {
            "vehicleRole": vehicleRole,
            "TxInterval": txInterval,
        }
        return field_to_api[field](cam_file, val)
    else:
        print("Provide label in CSV file to be verified")
        return -1


def vehicleRole(cam_file, *args):
    global _CAM_FILE_NAME
    VehicleRole_data = cam_file.loc[:, "VehicleRole"]
    Tx_Interval = cam_file.loc[:, "TxInterval"]
    sum = 0
    failed_list = []
    for index, intrv in enumerate(Tx_Interval):
        sum += int(intrv)
        if sum >= 500:
            if np.isnan(VehicleRole_data[index]):
                failed_list.append(index)
            sum = 0
            continue
        if not np.isnan(VehicleRole_data[index]):
            failed_list.append(index)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"LF container is not included in CAM immediately after 500 ms ")
        print("For manual verification refer:{}".format(_CAM_FILE_NAME))
        return "-1"
    print(f"LF container is included in CAM immediately after 500 ms")
    print("For manual verification refer:{}".format(_CAM_FILE_NAME))
    return 1


def txInterval(cam_file, *args):
    global _CAM_FILE_NAME
    Tx_Interval = cam_file.loc[:, "TxInterval"]
    failed_list = []
    for index, intrv in enumerate(Tx_Interval):
        if intrv <= 100 and intrv >= 1000:
            failed_list.append(index)
    if failed_list:
        print("Failure occurred at indices :{}".format(failed_list))
        print(f"CAM TX interval is not in valid range 100...1000")
        print("For manual verification refer:{}".format(_CAM_FILE_NAME))
        return "-1"
    print(f"CAM TX interval is in valid range 100...1000")
    print("For manual verification refer:{}".format(_CAM_FILE_NAME))
    return 1


def differance_between_TX_RX_time_stamp(child, cmd, *args):
    if len(args) >= 2:
        TX_file_path = f"{config.SAFE_FW_PATH}/resource/camlogs/{args[0]}"
        RX_file_path = f"{config.SAFE_FW_PATH}/resource/camlogs/{args[1]}"
        TX_file = pd.read_csv(TX_file_path)
        RX_file = pd.read_csv(RX_file_path)
        GenerationDeltaTime = list(RX_file['GenerationDeltaTime'])
        ts1_list = list(TX_file['Timestamp'])
        ts2_list = list(RX_file['Timestamp'])
        failed_list = []
        for index, DeltaTime in enumerate(GenerationDeltaTime):
            try:
                ind = list(TX_file['GenerationDeltaTime']).index(DeltaTime)
            except ValueError:
                ind = -1

            if ind != -1:

                timediff_in_ms = (datetime.datetime.strptime(ts2_list[index], "%m/%d/%Y-%H:%M:%S.%f") -
                                  datetime.datetime.strptime(ts1_list[ind],
                                                             "%m/%d/%Y-%H:%M:%S.%f")).microseconds * 0.001
                if timediff_in_ms > 150:
                    failed_list.append(index)

        if failed_list:
            print("Failure occurred at indices :{}".format(failed_list))
            print(f"CAM Timestamp diff is > 150")
            print("For manual verification refer:{}".format(RX_file_path))
            return "-1"
        print(f"CAM Timestamp diff is < 150ms")
        print("For manual verification refer:{}".format(RX_file_path))
        return 1
    else:
        print("Provide valid number of  parameters")
        return -1
