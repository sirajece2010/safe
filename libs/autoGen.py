'''
    File name: autoGen.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''
import sys
import re
import os
import config
from colorama import Fore


DEVICE = None
STATUS = None
_file_name_global = None
# we have to set _cleanup_flag after first time connecting to the device
# This is only for parsing the file
_cleanup_flag = None


def script_settings(script):
    SPACE = " " * 8
    NEWLINE = "\n"
    safe_path = config.SAFE_FW_PATH
    script.write("*** settings ***")
    script.write(NEWLINE)
    # script.write("Resource")
    # script.write(SPACE)
    # script.write("{}/config/conf_rsu.robot".format(safe_path))
    # script.write(NEWLINE)
    script.write("Library")
    script.write(SPACE)
    script.write("{}/libs/main.py".format(safe_path))
    script.write(NEWLINE)
    script.write("Library")
    script.write(SPACE)
    script.write("String")
    script.write(NEWLINE)
    script.write("Library")
    script.write(SPACE)
    script.write("OperatingSystem")
    script.write(NEWLINE * 2)


def script_variables(script):
    script.write("*** Variables ***\n")
    return 1


"""
This function sets the global varibles required for robot framework.
"""


def set_glo_var(cmd):
    glo_var = {
        "SPACE": " " * 8,
        "STATUS": None,
        "CMD": None,
        "DEVICE": None,
        "VAR": None
    }
    args = re.search(r"{([=\"\(\)@&#\d\w\s,-\\$\.%'{}^]+)}", cmd)
    global DEVICE
    global STATUS
    if args:
        cmd_var = args.group(1)
        cmd_var = re.split(r",", cmd_var)
        # "@" in str(cmd_var[0]):
        if re.search(r"^@.*", str(cmd_var[0]), re.I):
            status = cmd_var[0].strip()
            glo_var["STATUS"] = "${{{0}}}".format(status[1:])
            glo_var["VAR"] = [item.strip() for item in cmd_var[1:]]
        else:
            glo_var["STATUS"] = "${status}"
            glo_var["VAR"] = [item.strip() for item in cmd_var]
        command = cmd.split("{")
        command = command[0].strip()
        glo_var["CMD"] = command
        glo_var["DEVICE"] = DEVICE
        STATUS = glo_var["STATUS"]
        return glo_var
    else:
        glo_var["STATUS"] = "${status}"
        glo_var["CMD"] = cmd.strip()
        glo_var["DEVICE"] = DEVICE
        STATUS = glo_var["STATUS"]
        return glo_var

# @function:resets dmesg and meminfo starting of every testcase.


def script_testcases(testcase_commands, script):
    global _file_name_global
    global _cleanup_flag
    # resetting cleanup flag before parsing every testcase.
    _cleanup_flag = False
    script.write("*** TestCases ***\n")
    script.write(testcase_commands[0])
    func_struct = {
        "connect": connect_device,
        "config": commands,
        "show": commands,
        "check": check_status,
        "utils": commands,
        "obu": commands,
        "euobu": commands,
        "eursu": commands,
        "snmp": snmp_func,
        "gen": gen_func
    }
    status = "${status}"
    space = " " * 8
    jira_description = testcase_commands[0]  # We use this info to file bugs.
    script.write("{0}{1}={0}main.start_of_testcase{0}{2}\n\n".format(space,
                                                                     status,
                                                                     _file_name_global))
    script.write("{0}{1}={0}main.logger_config{0}{2}\n".format(space,
                                                               status,
                                                               _file_name_global))
    script.write("{0}{1}={0}main.jira_attributes_func{0}{2}\n".format(space,
                                                                      status,
                                                                      jira_description))
    for item in testcase_commands[1:]:
        cmd = item.strip()
        if re.search(r"^/\*.+", cmd, re.I):
            continue
        # Setting the global variable DEVICE
        if re.search(r"(^#RSU[\w]*(\d)+)|(^#OBU[\w]*(\d)+)|(^#EUOBU[\w]*(\d)+)", cmd, re.I):
            global DEVICE
            DEVICE = re.search(r"^#([\w\d]+).*", cmd)
            DEVICE = DEVICE.group(1)
            DEVICE = DEVICE.strip()
            continue
        elif cmd is "\n" or cmd is "":
            continue
        try:
            func_struct[cmd.split(" ")[0]](cmd, script)
            script.write("\n")
        except KeyError:
            commands(cmd, script)
            script.write("\n")
    script.write("{0}{1}={0}main.end_of_testcase".format(space,
                                                         status))
    return


def snmp_func(cmd, script):
    SPACE = " " * 8
    STATUS = "${status}"
    command = re.split(r"snmp", cmd, 1)[1]
    command = command.strip()
    script.write("{0}{1}={0}main.snmp_func{0}{2}".format(SPACE,
                                                         STATUS,
                                                         command))


def gen_func(cmd, script):
    SPACE = " " * 8
    args = re.search(r"{([=#@_\d\w\s,:/\(\)-\.%+]+)}", cmd)
    args = args.group(1)
    args = args.split(",")
    command = cmd.split("{")[0].strip()
    var = args[0]
    if re.search(r"^@.*", var):
        script.write("{0}${{{1}}}={0}{2}{0}{3}".format(SPACE,
                                                       var[1:],
                                                       "main.genFunc",
                                                       command))
    else:
        script.write("{0}${{{1}}}={0}{2}{0}{3}".format(SPACE,
                                                       "status",
                                                       "main.genFunc",
                                                       command))
    for arg in args[1:]:
        arg = arg.strip()
        if re.search(r"^@.*", arg, re.I):
            script.write("{0}${{{1}}}".format(SPACE, arg[1:]))
            continue
        script.write("{0}{1}".format(SPACE, arg))
    # script.write("{0}device={1}".format(SPACE, DEVICE))
    script.write("\n")
    # script.write("{}{}".format(SPACE, keyword))


def connect_device(cmd, script):
    global _cleanup_flag
    global DEVICE
    args = re.search(r"{([\d\w\s,]+)}", cmd)
    args = args.group(1)
    args = args.split(",")
    glo_var = set_glo_var(cmd)
    cleanup_device = None
    if re.search(r"RSU", glo_var["DEVICE"]):
        args = args[0]
        script.write(
            "{0}${{{1}}}={0}main.connect_to_device{0}{2}".format(glo_var["SPACE"],
                                                                 glo_var["DEVICE"],
                                                                 args))
        cleanup_device = "rsu"
    elif(re.search(r"^OBU", glo_var["DEVICE"])):
        args = args[0]
        script.write(
            "{0}${{{1}}}={0}main.obu_connect_to_device{0}{2}".format(glo_var["SPACE"],
                                                                     glo_var["DEVICE"],
                                                                     args))
        cleanup_device = "obu"
    elif(re.search(r"EUOBU", glo_var["DEVICE"])):
        script.write(
            "{0}${{{1}}}={0}main.obu_connect_to_device".format(glo_var["SPACE"],
                                                               glo_var["DEVICE"]))
        cleanup_device = "euobu"
        for arg in args:
            script.write("{0}{1}".format(glo_var["SPACE"], arg.strip()))
    else:
        print("wrong device")
    if not _cleanup_flag:
        _cleanup_flag = True  # setting _cleanup_flag
        script.write("\n")
        # This command clears dmesg and meminfo
        script.write(
            "{0}{1}={0}main.{4}_cleanup_func{0}${{{2}}}{0}{3}".format(glo_var["SPACE"],
                                                                      glo_var["STATUS"],
                                                                      glo_var["DEVICE"],
                                                                      DEVICE,
                                                                      cleanup_device))
    return


def commands(cmd, script):
    global DEVICE  # represents the device key e.x OBU1
    print(cmd)
    glo_var = set_glo_var(cmd)
    script.write(
        "{0}{3}={0}main.command{0}${{{1}}}{0}{2}{0}{4}".format(glo_var["SPACE"],
                                                               glo_var["DEVICE"],
                                                               DEVICE,
                                                               glo_var["STATUS"],
                                                               glo_var["CMD"]
                                                               ))
    if glo_var["VAR"] is not None:
        for arg in glo_var["VAR"]:
            if re.search(r"^@.*", arg):
                script.write("{0}${{{1}}}".format(glo_var["SPACE"], arg[1:]))
                continue
            script.write("{0}{1}".format(glo_var["SPACE"], arg))


def check_status(cmd, script):
    global DEVICE  # This represents the device ID e.x OBU1/OBU2 or RSU1
    SPACE = " " * 8
    args = re.search(r"{([=#@_\d\w\s,:/\(\)-\.%+\\*><']+)}", cmd)
    args = args.group(1)
    args = args.split(",")
    #print(cmd.split("{")[0].strip(), args)
    temp_cmd = cmd.split("{")[0].strip()
    print(temp_cmd, args)
    keyword = "Run Keyword      Should Be True      ${status}==1\n"
    if re.search(r"check status coc", temp_cmd):
        script.write("{0}{1}={0}main.check_status_coc".format(
            SPACE, "${status}"))
    else:
        script.write("{0}{1}={0}main.check_status".format(SPACE, "${status}"))
    for arg in args:
        arg = arg.strip()
        if re.search(r"^@.*", arg):
            script.write("{0}${{{1}}}".format(SPACE, arg[1:]))
            continue
        script.write("{0}{1}".format(SPACE, arg))
    script.write("{0}device={1}".format(SPACE, DEVICE))
    script.write("\n")
    script.write("{}{}".format(SPACE, keyword))


def fetch_dir_name(file_name):
    if re.search("^tcs", file_name):
        dir_name = "common"
    elif re.search("obu_coc", file_name):
        dir_name = "coc/obu/"
    elif re.search("rsu_coc", file_name):
        dir_name = "coc/rsu/"
    elif re.search("obu_kpi", file_name):
        dir_name = "kpi/obu/"
    elif re.search("rsu_kpi", file_name):
        dir_name = "kpi/rsu/"
    elif re.search("^obu_sdk", file_name):
        dir_name = "sdk/obu/"
    elif re.search("euobu_sdk", file_name):
        dir_name = "sdk/euobu"
    else:
        dir_name = re.split("_", file_name, 1)[0]
    return dir_name


"""
 Function to call three stages of parsing from .txt files to .robot scripts.
"""


def main(path):
    global _file_name_global
    path_to_file = path
    print(Fore.GREEN + "path to file:{}".format(path_to_file) + Fore.BLACK)
    file_name = os.path.basename(path_to_file)
    _file_name_global = file_name  # Assigning file_name to global variable
    dir_name = fetch_dir_name(file_name)
    print(Fore.GREEN + "dir name:{}".format(dir_name) + Fore.BLACK)
    script_file = "{}.robot".format(file_name.split(".")[0].strip())
    safe_path = os.path.abspath(config.SAFE_FW_PATH)
    with open(path_to_file, "r") as testcase,\
        open("{0}/scripts/{1}/{2}".format(safe_path,
                                          dir_name,
                                          script_file), "w+") as script:
        testcase_commands = testcase.readlines()
        script_settings(script)
        script_variables(script)
        script_testcases(testcase_commands, script)
    return None


if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print("Usage: python parser_db.py <path to the file>")
        exit(0)
    if len(sys.argv) is 2:
        path = sys.argv[1]
        main(path)
    elif len(sys.argv) > 2:
        for path in sys.argv[1:]:
            print(path)
            if re.search(r"(rsu)|(obu)|(euobu)|(eursu)|(tcs)[_\d\w]+\.txt$",
                         path, re.I):
                main(path)
