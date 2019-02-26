'''
    File name: wrapper.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''

import api_wrapper
api_wrapper_func = api_wrapper.api_wrapper_func
libRSE = api_wrapper.libRSE
re = api_wrapper.libRSE.re


def conf(child, command, *args):
    command = command.strip()
    command = re.sub(r"(\s+)", " ", command)
    if len(args) != 0:
        return libRSE.run_command_config(child, command, *args)
    else:
        return libRSE.run_command_config(child, command)


def show(child, command, *args):
    command = command.strip()
    command = re.sub(r"(\s+)", " ", command)
    if len(args) != 0:
        return api_wrapper_func(command)(child, command, *args)
    else:
        return api_wrapper_func(command)(child, command)


def utils(child, command, *args):
    command = command.strip()
    command = re.sub(r"(\s+)", " ", command)
    if len(args) != 0:
        return api_wrapper_func(command)(child, command, args[0])
    elif "utils copy" in command:
        return libRSE.scp_command_cli(child, command)
    else:
        return api_wrapper_func(command)(child, command)


def file_conf(child, command, *args):
    command = command.strip()
    command = re.sub(r"(\s+)", " ", command)
    return api_wrapper_func(command)(child, command, *args)


def wrapper_func(value, cmd):
    data_struct = {"show": show,
                   "config": conf,
                   "utils": utils,
                   "file": file_conf
                   }
    try:
        return data_struct[value]
    except KeyError:
        return api_wrapper_func(cmd)