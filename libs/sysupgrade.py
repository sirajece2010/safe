#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 14 11:22:43 2018

@author: raviteja
"""
import re
import os
import config
import glob
import libRSE
import sys
from time import sleep
import time
import pexpect


def rsu_upgrade(device, img_path, sys_dtils=None):
    os.chdir(img_path)
    imgs = glob.glob("SW1000*emmc.image")
    img_name = max(imgs, key=os.path.getctime)
    print("LatestImage:{}".format(img_name))
    child = libRSE.connect_to_device(device)
    utils_copy = "utils copy \
    savari:scp://192.168.20.23://mnt/root/CI/builds/RSU/{0}\
    image:{0}".format(img_name)
    print(utils_copy)
    libRSE.scp_command_cli(child, utils_copy)
    print("Image successfully copied")
    sleep(10)
    child.sendline("utils rsu-upgrade -n {}\r".format(img_name))
    child.close()
    print("Device is upgrading to image:{}".format(img_name))
    print("Going for sleep 300 seconds")
    sleep(300)
    child = libRSE.connect_to_device(device)
    ver = libRSE.show_version(child, "show version")
    print("Upgraded version:{}".format(ver))
    ver_num = re.search(r"-([\w\.]+)", ver).group(1)
    if re.search(ver_num, img_name):
        print("Succefully upgraded")
        return 1
    else:
        print("Build not upgraded properly")
        return -1
    child.close()


def obu_upgrade(device, img_path, sys_dtils=None):
    os.chdir(img_path)
    imgs = glob.glob("MW1000*emmc.image")
    img_name = max(imgs, key=os.path.getctime)
    print("LatestImage:{}".format(img_name))
    child = libRSE.obu_connect_to_device(device)
    source = "/mnt/root/CI/builds/ASD/{}".format(img_name)
    print(time.time())
    libRSE.obu_scp_sys(child, "scp", source, "/tmp/")
    print("AFTER", child.after)
    print("Image successfully copied")
    sleep(10)
    image_path = "sysupgrade -n /tmp/{}\n".format(img_name)
    print(image_path)
    child.sendline("sync")
    child.expect(config.OBUPMT)
    print("BEFORE", child.before)
    print("AFTER", child.after)
    try:
        print("Sending the upgrade command")
        child.send("{}".format(image_path))
        child.expect(config.OBUPMT)
        print("AFTER", child.after)
        print("CHILD BEFORE", child.before)
    except (pexpect.EOF, pexpect.TIMEOUT):
        print("its ok")
    print("Device is upgrading to image:{}".format(img_name))
    print("Going for sleep 300 seconds")
    child.close()
    sleep(300)
    child = libRSE.obu_connect_to_device(device)
    ver = libRSE.obu_cat(child, "obu cat", "/etc/banner")
    print("Upgraded version:{}".format(ver))
    ver = re.search(r"-([\w\.]+)", ver).group(1)
    print(ver)
    if re.search(ver, img_name):
        print("Successfully upgraded")
        libRSE.obu_reset_func(child, "obu reset", True)
        return 0
    else:
        print("Build not upgraded properly")
        return -1


if __name__ == "__main__":
    device = sys.argv[1]
    dev_dtils = None
    sys_dtls = {
        "UNAME": "savari",
        "HOSTIP": "192.168.20.23",
        "PASSWD": "k)n64olrUU{mYRc"
    }
    imgdir = {
        "rsu": "/mnt/root/CI/builds/RSU",
        "obu": "/mnt/root/CI/builds/ASD"
    }
    if re.search("rsu", device, re.I):
        rsu_upgrade(device, imgdir["rsu"])
    elif re.search("obu", device, re.I):
        obu_upgrade(device, imgdir["obu"])
