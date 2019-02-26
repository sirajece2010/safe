# -*- coding: utf-8 -*-
'''
    File name: config.py
    Author: Ravi Teja Nagamothu
    Date created: 7/11/2017
    Python Version: 3.6
'''
# ******* Global PATH ***********
SAFE_FW_PATH = "/home/innominds/Innominds/Automation/safe"
# ******* Variables Declaration ***************
RSU_Dict = {}
OBU_Dict = {}
SERVER_Dict = {}
WPS_Dict = {}
OBU_kpi = {}
SAFE_RES_PATH = {}
SNMP_Dict = {}
# ***********RSU Login Credentials*************
# "RSU0" is a special key device.Dont change it or dont give it as a key in
# writing script files. It is not associated with any ip address.
RSU_Dict["RSU0"] = {
    "UNAME": "root",
    "ROOT_UNAME": "root",
    "HOSTIP": None,
    "PORT": "51012",
    "PASSWORD": "1[8V:2<J5*W;2I16H1nu",
    "PR_PASSWORD": "6efre#ESpe",
    "ROOT_PASSWORD": "1[8V:2<J5*W;2I16H1nu"
}

RSU_Dict["RSU1"] = {
    "UNAME": "root",
    "ROOT_UNAME": "root",
    "HOSTIP": "10.0.0.232",
    "PORT": "51012",
    "PASSWORD": "1[8V:2<J5*W;2I16H1nu",
    "PR_PASSWORD": "6efre#ESpe",
    "ROOT_PASSWORD": "1[8V:2<J5*W;2I16H1nu"
}
RSU_Dict["RSU2"] = {
    "UNAME": "root",
    "ROOT_UNAME": "root",
    "HOSTIP": "10.0.0.223",
    "PORT": "51012",
    "PASSWORD": "1[8V:2<J5*W;2I16H1nu",
    "PR_PASSWORD": "6efre#ESpe",
    "ROOT_PASSWORD": "1[8V:2<J5*W;2I16H1nu"
}
RSU_Dict["RSUIPV6"] = {
    "UNAME": "root",
    "ROOT_UNAME": "root",
    "HOSTIP": "2001:db8:f101:9000::12",
    "PORT": "51012",
    "PASSWORD": "1[8V:2<J5*W;2I16H1nu",
    "PR_PASSWORD": "6efre#ESpe",
    "ROOT_PASSWORD": "1[8V:2<J5*W;2I16H1nu"
}
SNMP_Dict["SNMP3"] = {
    "UNAME": "admin",
    "PASSWD": "tUrnFrf@1rb@nk$",
    "KEYPSWD": "tUrnGrf@1rb@nk$",
    "IP": "10.0.0.232",
    "PATHMIB": "/usr/local/share/snmp/mibs/"
}
# ***********RSU commands************************
CLIPMT = "StreetWAVE>>"
SHELLPMT = r"StreetWAVE:.+#"
SHELL_CMD = "shell-drop"
PR_MODE = "privileged-mode enable"
NSEC = "2"    # cpu-usage nsec may be specified here or can be provided as a
# parametre in writing script files.

# **********OBU Login Credentials*************************

# "OBU0" is a special key device.Dont change it or dont give it as a key in
# writing script files. It is not associated with any ip address.
OBU_Dict["OBU0"] = {
    "OBU_UNAME": "root",
    "HOSTIP": None,
    "OBU_PASSWORD": "5@G3p9axINJA"
}

OBU_Dict["OBU2"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "10.0.0.184",
    "OBU_PASSWORD": "5@G3p9axINJA"
}
OBU_Dict["OBU1"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "10.0.0.237",
    "OBU_PASSWORD": "5@G3p9axINJA"
}
OBU_Dict["OBU3"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "10.0.0.199",
    "OBU_PASSWORD": "5@G3p9axINJA"
}
OBU_Dict["OBU1IPV6"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "2001:db8:f101:9000::13",
    "OBU_PASSWORD": "5@G3p9axINJA"
}
OBU_Dict["EUOBU1"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "10.0.0.243",
    "OBU_PASSWORD": "5@G3p9axINJA"
}

OBU_Dict["EUOBU2"] = {
    "OBU_UNAME": "root",
    "OBU_HOSTIP": "10.0.0.242",
    "OBU_PASSWORD": "5@G3p9axINJA"
}

# OBU AND ETSI PMTS (CONSTANTS) NEVER CHANGE THESE VALUES IN ANY OF THE API's
_OBUPMT = "US16SIQC:?.+#"
_EUOBUPMT = "EU16SIQC:.+#"
# ***********WEB POWER SWITCH COMMANDS************
WPS_Dict["SWITCH1"] = {
    "WPS_UNAME": "admin",
    "WPS_HOSTIP": "10.0.0.250",
    "WPS_PASSWORD": "1234"
}
# ***********OBU COMMANDS *********************
OBUPMT = "US16SIQC:?.+#"
# We don't use "EUOBUPMT" in API's for ETSI stack.
# Instead we are using OBUPMT by asiging OBUPMT = EUOBUPMT in obu_connect_to_device
EUOBUPMT = "EU16SIQC:.+#"
# **********SYSTEM_SERVER COMMANDS*********************
SYS_UNAME = "innominds"
SYS_HOST = "192.168.101.107"
SYS_PASSWORD = "inno@123"
PATH = "/home/innominds/"
from_mail="sirajece10@gmail.com"
to_mail="sirajece2010@gmail.com"
mail_passwd="kamsahameed"
#IMG_NAME = "SW1000-I.MX6-ext4-5.9.0.73-sd.image"
IMG_NAME = {"OBU_IMAGE_NAME_1":"resource/files/MW1000-I.MX6-ext4-6.0.99.24-emmc.image",
           "OBU_IMAGE_NAME_2":"resource/files/openwrt-imx6-flex-emmc.img",
           "RSU_IMAGE_NAME_1":"resource/files/SW1000-I.MX6-ext4-6.0.99.24-emmc.image",
           "RSU_IMAGE_NAME_2":""}

# *********SCRIPT VARIABLES ********************
scr_var = {}
scr_var["ipv4"] = ["192.168.20.33", "192.168.20.25"]
scr_var["IPV6"] = []
scr_var["PSID"] = []
scr_var["ip-tables"] = []
scr_var["timpr"] = ["status", "db-filepath", "streaming-mode",
                    "streaming-port", "streaming-ip", "certificate-attachrate", "ssp-list"]
scr_var["tcd_review"] = ["map-psid", "status", "mode",
                         "tc-ipaddr", "spat-signature", "map-signature"]
scr_var["im_fwd_review"] = ["enable", "tcdlisten"]
scr_var["str_rpt_review"] = [
    "status", "streaming-port", "certificate-attachrate"]
scr_var["list_certi"] = ["security-context", "certificates", "wscs", "revoked_certs", "certificates_wsa",
                         "certificates_tim", "certificates_spat", "certificates_map", "certificates_rtcm", "crypto.state"]
scr_var["rsu_mib"] = ["rsu-mib.txt", "RSU41_Savari_MIB.txt", "reboot_time.txt"]
scr_var["timdb_cli"] = ["timfile.db"]
scr_var["tcd_list"] = ["Sample_Map_Haggerty_12mile.xml", "sample_xml_file_old_region_shape.xml", "sample_xml_file_old_region_region.xml",
                       "sample_xml_file_old_region_circle.xml", "sample_xml_file_offset_system_georepeated.xml", "sample_xml_file_offset_system.xml", "sample_xml_file_geographic_path.xml"]
#  ********** KPI Variables *********************
OBU_kpi = {"OBU_SECURITY": "0",
           "OBU_CHANNEL": "176",
           "OBU_MAX_RV": "100",
           "OBU_APP": "0x77FFFFF",
           "OBU_CONGESTION": "0",
           "OBU_MODE": "2",
           "OBU_EXTRAP": "0",
           "OBU_repen": "1",
           "OBU_TIMEN": "0",
           "OBU_SPATEN": "0",
           "OBU_TAP": "0",
           "OBU_NP": "0",
           "OBU_LOG": "0",
           "OBU_SLOG": "0",
           "RES_PATH_GEN": "/home/savari/Desktop/temp_auto/Automation/safe/logs/kpi/",
           "RES_PATH_ALL": "/home/savari/Desktop/temp_auto/Automation/safe/logs/kpi/all_log/"}
