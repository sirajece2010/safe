'''
    File name: genLib.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''
import config
from time import sleep
import libRSE


def value_at_index(*args):
    lst = args[0]
    index = args[1]
    return lst[int(index)]


'''def math_operation_func(*args):
    val1 = float(args[0])
    val2 = float(args[1])
    symb = args[2]
    symb_dict = {
        "add": val1 + val2,
        "sub": val1 - val2,
        "mul": val1 * val2
    }
    try:
        symb_dict["div"]=val1 / val2
        symb_dict["rem"]=val1 // val2
    except ZeroDivisionError:
        print("ZeroDivisionError exception occured")
        symb_dict["div"]=-1
        symb_dict["rem"]=-1
    try:
        result = symb_dict[symb]
        return result
    except KeyError:
        print("Please provide valid math operator")'''

def math_operation_func(*args):
    # val1 = int(args[0])
    # val2 = int(args[1])
    symb = args[2]

    symb_dict = {
        "add": "+",
        "sub": "-",
        "div": "/",
        "rem": "//",
        "mul": "*"
    }


    try:
        result = eval("{} {} {}".format(args[0], symb_dict[symb], args[1]))
        return result
    except ZeroDivisionError:
        print("Zero division error exception occured")
        return None
    except KeyError:
        print("Please provide valid math operator")


def file_backup_fun_RSU(child, device):
    os = libRSE.os
    pexpect = libRSE.pexpect
    datetime = libRSE.datetime
    HOME = os.getenv("HOME")
    print("Command failure occurred. Backing up system logs.")
    child.sendline("\r")
    try:
        child.expect(config.CLIPMT)
        libRSE.direct_to_shell_mode(child, "direct to shell mode", device)
    except pexpect.TIMEOUT:
        child.expect(config.SHELLPMT)
        print("In shell mode")
    child.sendline("")
    child.expect(config.SHELLPMT)
    print("Started copying /nojournal/...")
    # SAFE_FW_PATH = os.path.abspath(config.SAFE_FW_PATH)
    time_stamp = datetime.datetime.now().strftime("%b_%d_%I:%M:%S_%Y")
    path_to_logs = "{0}/SAFElogs/nojournal/{1}_rsunojournal".format(HOME,
                                                                    time_stamp)
    os.mkdir(path_to_logs)
    scp_cmd = "scp -r /nojournal/ {0}@{1}:{2}".format(config.SYS_UNAME,
                                                      config.SYS_HOST,
                                                      path_to_logs
                                                      )
    print(scp_cmd)
    child.sendline(scp_cmd)
    try:
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("y\r")
        child.expect("password")
        child.sendline(config.SYS_PASSWORD)
    try:
        child.expect(config.SHELLPMT, timeout=12000)
    except pexpect.TIMEOUT:
        print("Faild to backup")
    libRSE.exit_fun(child, "exit")
    return 1


def file_backup_fun_OBU(child):
    try:
        os = libRSE.os
        pexpect = libRSE.pexpect
        datetime = libRSE.datetime
        HOME = os.getenv("HOME")
        child.expect(config.OBUPMT)
        print("Started copying /nojournal/...")
        # SAFE_FW_PATH = os.path.abspath(config.SAFE_FW_PATH)
        time_stamp = datetime.datetime.now().strftime("%b_%d_%I:%M:%S_%Y")
        path_to_logs = "{0}/SAFElogs/nojournal/{1}_obunojournal".format(
            HOME,
            time_stamp)
        os.mkdir(path_to_logs)
        scp_cmd = "scp -r /nojournal/ {0}@{1}:{2}".format(config.SYS_UNAME,
                                                          config.SYS_HOST,
                                                          path_to_logs
                                                          )
        print(scp_cmd)
        child.sendline(scp_cmd)
        try:
            child.expect("password")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting")
            child.sendline("y\r")
            child.expect("password")
            child.sendline(config.SYS_PASSWORD)
        child.expect(config.OBUPMT, timeout=12000)
    except pexpect.TIMEOUT:
        print("Timeout happened while backing up nojournal/")
        return None
    return 1


def file_backup_fun(child, device):
    re = libRSE.re
    if re.search(r"rsu", device, re.I):
        file_backup_fun_RSU(child, device)
    elif re.search(r"obu", device, re.I):
        file_backup_fun_OBU(child)
    return 1

def string_operation_func(*args):
    """ Author: Nilesh Guhe
    """
    symb_dict = {
        "add": args[0] + " {}".format(args[1])
    }
    try:
        result = symb_dict['add']
        return result
    except KeyError:
        print("Please provide valid string syntax")
