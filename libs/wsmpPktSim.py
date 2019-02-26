import json

import re
import copy
import sys
import json
import config
from functools import reduce
import os
from time import sleep
import socket
import itertools
import datetime
import random
from collections import OrderedDict
from colorama import Fore
import argparse
_sequence = list()
_payload = ""
_index = 0
_hexdump_deflt = "0b030f01b210010c0401940080078148038100400380818e3f0103110\
164060a3d5c32d999888e002fd50709085553444f543232310123090308050453434d530910\
000000000000000000000000000000000a023edc0111ae9a8c01020c1003440000234400004\
343000062320000150102070820010db8f101800000000000000000004020010db8f1018000\
000000000000001520010db8f1019000000000000000000500700187000199db17133467000\
199db18dcf7e707b74d6c2e3ebc131f6581010100030180ecb64e61538ca00d308000003200\
000000000000000000000000001874e38586000f00010180018780008183fec99cd76b4c234\
97add6a8ac4b9012e1ced339cccc7578bb95bcc337a9490b58083990dd09590ed88cba9b86a\
3b1cf5f10df6b2fc25524453d0a03aa2b7bea2a768ac6de5cd2e4c5fcfeaad5f5624235278c\
3298322b60635f3e6f81cdf2016ce4b"

_HOME = os.getenv("HOME")


def _set_env():
    global _HOME
    if not os.path.exists("{}/pktSimFiles".format(_HOME)):
        os.mkdir("{}/pktSimFiles".format(_HOME))


# Info element Dictionary
Info_elm_Dict = {
    4: "tx_pwr_used",
    5: "2d_location",
    6: "3d_location",
    7: "advt_idnt",
    8: "prv_serv_cntxt",
    9: "ipv6_addr",
    10: "serv_port",
    11: "prv_mac_addr",
    12: "edca_par_set",
    13: "sec_dns",
    14: "gw_mac_addr",
    15: "ch_num",
    16: "data_rate",
    17: "repeat_rate",
    19: "rcpi_threshhold",
    20: "wsa_cnt_threshhold",
    21: "ch_access",
    22: "wsa_cnt_threshhold_intrvl",
    23: "ch_load"
}
# Info element Dictionary definitions
SECURED = None
UNSECURED = None
Info_elm_Dict_def = None
wave_info_elm_ext = None
N_head = None
info_elm = None
T_head = None
wsa_head_info_elm_ext = None
wsa_head = None
sis_wave_info_elm_ext = None
serv_info_inst = None
wsa_serv_info_seg = None
cis_wave_info_elm_ext = None
ch_info_inst = None
wsa_ch_info_seg = None
rout_wave_info_elm_ext = None
wsa_routing_advt = None
wsa = None
wsm = None
wsm_data = None
wsmp = None


def wsmp_head_init():
    global SECURED, UNSECURED, Info_elm_Dict_def, wave_info_elm_ext
    global N_head, info_elm, T_head, wsa_head_info_elm_ext, wsa_head
    global sis_wave_info_elm_ext, serv_info_inst, wsa_serv_info_seg
    global cis_wave_info_elm_ext, ch_info_inst, wsa_ch_info_seg
    global rout_wave_info_elm_ext, wsa_routing_advt, wsa, wsm, wsm_data, wsmp
    global _index
    _index = 0
    SECURED = 0
    UNSECURED = 0
    Info_elm_Dict_def = {
        "tx_pwr_used": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "2d_location": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "3d_location": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "advt_idnt": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "prv_serv_cntxt": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "ipv6_addr": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "serv_port": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "prv_mac_addr": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "edca_par_set": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "sec_dns": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "gw_mac_addr": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "ch_num": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "data_rate": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "repeat_rate": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "rcpi_threshhold": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "wsa_cnt_threshhold": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "ch_access": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "wsa_cnt_threshhold_intrvl": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        },
        "ch_load": {
            "elm_id": None,
            "elm_len": None,
            "elm_val": None
        }
    }
    wave_info_elm_ext = {
        "count": None,
        "info_elm": dict()  # list()
    }
    N_head = {
        "subtype": None,  # 4 bits; 0-2^4
        "opt_ind": None,  # 1 bit
        "version": None,  # 3 bit
        "wave_info_elm_ext": wave_info_elm_ext,
        "TPID": None
    }
    info_elm = {
        "elm_id": None,
        "elm_len": None,
        "elm_val": None
    }
    T_head = {
        "PSID": None,
        "wsm_len_before": None,
        "secured": SECURED,
        "unsecured": UNSECURED,
        "wsm_len_after": None,
    }
    wsa_head_info_elm_ext = {
        "count": None,
        "info_elm": dict()
    }
    wsa_head = {
        "version": None,  # 4 bits 0-2^4
        "opt_ind": None,  # 4 bits
        "wsa_id": None,  # 4 bits
        "cntnt_cnt": None,  # 4 bits
        "wsa_head_info_elm_ext": wsa_head_info_elm_ext
    }
    sis_wave_info_elm_ext = {
        "count": None,
        "info_elm": dict()
    }
    serv_info_inst = {
        "PSID": None,
        "ch_ind": None,  # 5 bits
        "reserved": None,  # 2 bits
        "opt_in": None,  # 1 bit
        "sis_wave_info_elm_ext": sis_wave_info_elm_ext
    }
    wsa_serv_info_seg = {
        "count": None,
        "serv_info_inst": list()  # we append num of serv_info_inst
    }
    cis_wave_info_elm_ext = {
        "count": None,
        "info_elm": dict()
    }
    ch_info_inst = {
        "operating_class": None,
        "ch_num": None,
        "tx_pwr_level": None,
        "adaptable": None,  # 1 bit
        "data_rate": None,  # 7 bits
        "ch_info_opt_ind": None,
        "cis_wave_info_elm_ext": cis_wave_info_elm_ext
    }
    wsa_ch_info_seg = {
        "count": None,
        "ch_info_inst": list()
    }
    rout_wave_info_elm_ext = {
        "count": None,
        "info_elm": dict()
    }

    wsa_routing_advt = {
        "router_lifetime": None,
        "ip_prefix": None,
        "prefix_len": None,
        "default_gateway": None,
        "primary_dns": None,
        "rout_wave_info_elm_ext": rout_wave_info_elm_ext
    }
    wsa = {
        "wsa_head": wsa_head,
        "wsa_serv_info_seg": wsa_serv_info_seg,
        "wsa_ch_info_seg": wsa_ch_info_seg,
        "wsa_routing_advt": wsa_routing_advt
    }
    wsm = None
    wsm_data = {
        "wsa": wsa,
        "wsm": wsm
    }

    wsmp = {
        "N-head": N_head,
        "T-head": T_head,
        "wsm_data": wsm_data
    }
    return 1


def wsmp_head_dec(wsmp_dump):
    wsmp_dump = wsmp_n_head_dec(wsmp_dump)
    wsmp_dump = wsmp_t_head_dec(wsmp_dump)
    return wsmp_dump


def wsmp_n_head_dec(wsmp_dump):
    global N_head
    global _index
    hex_code = int(wsmp_dump[_index:_index + 2], 16)
    N_head["subtype"] = (hex_code & 240) >> 4
    _sequence.append(("wsmp subtype", _index))
    opt_ind = (hex_code & 8) >> 3  # opt ind is one bit size
    N_head["opt_ind"] = opt_ind
    _sequence.append(("wsmp option ind", _index))
    N_head["version"] = hex_code & 7
    _sequence.append(("wsmp version", _index))
    _index += 2
    if N_head["opt_ind"]:
        wsmp_dump = wave_info_elm_ext_dec(wsmp_dump)
        N_head["TPID"] = int(wsmp_dump[_index:_index + 2], 16)
        _sequence.append(("wsmp TPID", _index))
        _index += 2
        return wsmp_dump
    else:
        N_head["TPID"] = int(wsmp_dump[_index:_index + 2], 16)
        _sequence.append(("wsmp TPID", _index))
        _index += 2
        return wsmp_dump


def wave_info_elm_ext_dec(wsmp_dump):
    global wave_info_elm_ext
    global Info_elm_Dict_def
    global Info_elm_Dict
    global _sequence
    global _index
    wave_info_elm_ext["count"] = int(wsmp_dump[_index:_index + 2], 16)
    _sequence.append(("wsmp count", _index))
    _index += 2
    for elm in range(wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[_index:_index + 2], 16)
        info_elm_name = Info_elm_Dict[info_elm_id]
        _sequence.append((info_elm_name, _index))
        _index += 2
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[_index:_index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        _sequence.append(("{}_len".format(info_elm_name), _index))
        _index += 2
        elm_val = wsmp_dump[_index:_index + (2 * elm_len)]
        Info_elm_Dict_def[info_elm_name]["elm_val"] = elm_val
        _sequence.append(("{}_val".format(info_elm_name), _index))
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        _index = _index + 2 * elm_len
        wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    return wsmp_dump


def wsmp_t_head_dec(wsmp_dump):
    global T_head
    global _sequence
    global _index

    def psid_len_calc(psid_dump):
        num = int(psid_dump, 16)
        if num < 8:
            return 1
        elif num < 12:
            return 2
        elif num < 14:
            return 3
        else:
            return 4

    def wsm_len_calc(dump, sec_head_pos, unsec_head_pos):
        global _index
        global _sequence
        if sec_head_pos:
            global SECURED
            SECURED = 1
            T_head["secured"] = SECURED
            _sequence.append(("wsm_len_before", _index))
            _index = sec_head_pos.start()
            _sequence.append(("wsmp secured", _index))
            wsm_len_octets = sec_head_pos.start() // 2
            return wsm_len_octets
        else:
            global UNSECURED
            UNSECURED = 1
            T_head["unsecured"] = UNSECURED
            _sequence.append(("wsmp unsecured", _index))
            _index = unsec_head_pos.start()
            wsm_len_octets = unsec_head_pos.start() // 2
            return wsm_len_octets
    psid_len = psid_len_calc(wsmp_dump[_index])
    T_head["PSID"] = int(wsmp_dump[_index:_index + psid_len * 2], 16)
    _sequence.append(("wsmp PSID", _index))
    _index += psid_len * 2  # getting num of chr required for PSID
    sec_head_pos = re.search("03810040", wsmp_dump)
    unsec_head_pos = re.search("0380", wsmp_dump)
    wsm_len_octets = wsm_len_calc(wsmp_dump, sec_head_pos,
                                  unsec_head_pos)
    wsm_len_val = int(wsmp_dump[:wsm_len_octets * 2], 16)
    if wsm_len_val < 128:
        T_head["wsm_len_before"] = wsm_len_val
    else:
        T_head["wsm_len_before"] = wsm_len_val - 32768
    if sec_head_pos:
        _index = unsec_head_pos.start()
        _sequence.append(("wsmp unsecured", _index))
        _index = unsec_head_pos.end()
        _sequence.append(("wsmp_len_after", _index))
    # wsmp_dump = wsmp_dump[_index:]
    if T_head["PSID"] == 0x8007:
        wsa_len_val = int(wsmp_dump[_index:_index + 2], 16)
        if wsa_len_val < 128:
            T_head["wsm_len_after"] = wsa_len_val
            _index += 2
            # wsmp_dump = wsmp_dump[_index:]
        else:
            wsa_len_val = int(wsmp_dump[_index:_index + 4], 16)
            T_head["wsm_len_after"] = wsa_len_val - 32896
            _index += 4
            # wsmp_dump = wsmp_dump[_index:]
    else:
        wsa_len_val = int(wsmp_dump[:2], 16)
        if wsa_len_val < 128:
            T_head["wsm_len_aft"] = wsa_len_val
            _index += 2
            # wsmp_dump = wsmp_dump[_index:_index+2]
        else:
            wsa_len_val = int(wsmp_dump[:4], 16)
            T_head["wsm_len_aft"] = wsa_len_val - 32896
            _index += _index + 4
            # wsmp_dump = wsmp_dump[_index:_index+4]
    return wsmp_dump


def wsa_head_info_elm_ext_dec(wsmp_dump):
    global wsa_head_info_elm_ext
    global Info_elm_Dict_def
    global Info_elm_Dict
    global _sequence
    global _index
    wsacode = int(wsmp_dump[_index:_index + 2], 16)
    # wsmp_dump = wsmp_dump[2:]
    wsa_head_info_elm_ext["count"] = wsacode
    _sequence.append(("wsa_head_info_elm_ext_count", _index))
    _index += 2
    for elm in range(wsa_head_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[_index:_index + 2], 16)
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        _sequence.append((info_elm_name, _index))
        _index += 2
        elm_len = int(wsmp_dump[_index:_index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        _sequence.append(("{}_elm_len".format(info_elm_name), _index))
        _index = _index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[_index:_index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        _sequence.append(("{}_elm_val".format(info_elm_name), _index))
        _index = _index + 2 * elm_len
        wsa_head_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    #wsmp_dump = wsmp_dump[_index:]
    lat_long_ele_conv()
    return wsmp_dump


def ch_info_inst_get(PSID, option):
    ch_index = None
    psid_int = int(PSID)
    psid_list = [seg["PSID"] for seg in wsa_serv_info_seg["serv_info_inst"]]
    if psid_int in psid_list:
        ch_index = [seg["ch_ind"] for seg in
                    wsa_serv_info_seg["serv_info_inst"]
                    if seg["PSID"] == psid_int]
    else:
        return "-1"
    try:
        if re.search("count", option):
            return wsa_ch_info_seg[option]
        ch_info_data = \
            wsa_ch_info_seg["ch_info_inst"][ch_index[0] - 1]
        value = ch_info_data[option]
        return value if value is not None else "-1"
    except IndexError:
        return "-1"


def serv_info_inst_get(psid=None, option=None, count=None):
    psid_int = int(psid)
    # This API is used to get the info values of Service Info Seg
    psid_list = [seg["PSID"] for seg in wsa_serv_info_seg["serv_info_inst"]]
    psid_list_dict = [seg for seg in
                      wsa_serv_info_seg["serv_info_inst"]]
    if re.search(r"PSID", option):
        return psid_int if psid_int in psid_list else "-1"
    if option:
        for info_dict in psid_list_dict:
            return info_dict[option] if info_dict["PSID"] == psid_int \
                else "-1"


def sis_wave_info_elm_ext_dec(wsmp_dump):
    global sis_wave_info_elm_ext
    global _sequence
    global _index
    elmcnt = int(wsmp_dump[_index:_index + 2], 16)
    sis_wave_info_elm_ext["count"] = elmcnt
    _sequence.append(("sis_wave_info_elm_ext_count", _index))
    _index += 2
    for elm in range(sis_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[_index:_index + 2], 16)
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        _sequence.append((info_elm_name, _index))
        _index += 2
        elm_len = int(wsmp_dump[_index:_index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        _sequence.append(("{}_elm_len".format(info_elm_name), _index))
        _index += 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[_index:_index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        _sequence.append(("{}_elm_val".format(info_elm_name), _index))
        _index = _index + 2 * elm_len
        sis_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    #wsmp_dump = wsmp_dump[_index:]
    return wsmp_dump


def serv_info_inst_dec(wsmp_dump):
    global sis_wave_info_elm_ext
    global serv_info_inst
    global _sequence
    global _index

    def psid_len_calc(psid_dump):
        num = int(psid_dump, 16)
        if num < 8:
            return 1
        elif num < 12:
            return 2
        elif num < 14:
            return 3
        else:
            return 4
    psid_len = psid_len_calc(wsmp_dump[_index])
    psid = int(wsmp_dump[_index:_index + psid_len * 2], 16)
    serv_info_inst["PSID"] = psid
    _sequence.append(("serv_info_inst_psid", _index))
    _index += psid_len * 2
    siscode = int(wsmp_dump[_index:_index + 2], 16)
    serv_info_inst["ch_ind"] = (siscode & 248) >> 3  # 5 bits
    _sequence.append(("serv_info_inst_ch_ind", _index))
    serv_info_inst["reserved"] = (siscode & 6) >> 1  # 2 bits
    _sequence.append(("serv_info_inst_reserved", _index))
    serv_info_inst["opt_in"] = (siscode & 1)  # 1 bit
    _sequence.append(("serv_info_inst_opt_in", _index))
    _index += 2
    # wsmp_dump = wsmp_dump[_index:]
    if serv_info_inst["opt_in"]:
        wsmp_dump = sis_wave_info_elm_ext_dec(wsmp_dump)
    return wsmp_dump


def wsa_serv_info_seg_dec(wsmp_dump):
    global wsa_serv_info_seg
    global serv_info_inst
    global _sequence
    global _index
    siscount = int(wsmp_dump[_index:_index + 2], 16)
    wsa_serv_info_seg["count"] = siscount
    _sequence.append(("wsa_serv_info_seg_count", _index))
    _index += 2
    # wsmp_dump = wsmp_dump[_index:]
    for sis_elm in range(wsa_serv_info_seg["count"]):
        wsmp_dump = serv_info_inst_dec(wsmp_dump)
        wsa_serv_info_seg["serv_info_inst"].append(
            copy.deepcopy(serv_info_inst))
    return wsmp_dump


def cis_wave_info_elm_ext_dec(wsmp_dump):
    global cis_wave_info_elm_ext
    global _sequence
    global _index
    count = int(wsmp_dump[_index:_index + 2], 16)
    cis_wave_info_elm_ext["count"] = count
    _sequence.append(("cis_wave_info_elm_ext_count", _index))
    _index += 2
    for ciselm in range(cis_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[_index:_index + 2], 16)
        info_elm_name = Info_elm_Dict[info_elm_id]
        _sequence.append((info_elm_name, _index))
        _index += 2
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[_index:_index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        _sequence.append(("{}_elm_len".format(info_elm_name), _index))
        _index += 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[_index:_index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        _sequence.append(("{}_elm_val".format(info_elm_name), _index))
        _index = _index + 2 * elm_len
        cis_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    # wsmp_dump = wsmp_dump[_index:]
    return wsmp_dump


def ch_info_inst_dec(wsmp_dump):
    global ch_info_inst
    global cis_wave_info_elm_ext
    global _sequence
    global _index
    operating_class = int(wsmp_dump[_index:_index + 2], 16)
    _sequence.append(("ch_info_inst_operating_class", _index))
    _index += 2
    ch_num = int(wsmp_dump[_index:_index + 2], 16)
    _sequence.append(("ch_info_inst_ch_num", _index))
    _index = _index + 2
    tx_pwr_level = int(wsmp_dump[_index:_index + 2], 16)
    _sequence.append(("ch_info_inst_tx_pwr_level", _index))
    _index = _index + 2
    adaptable = (int(wsmp_dump[_index:_index + 2], 16) & 128) >> 7
    _sequence.append(("ch_info_inst_adaptable", _index))
    data_rate = (int(wsmp_dump[_index:_index + 2], 16) & 127)
    _sequence.append(("ch_info_inst_data_rate", _index))
    _index = _index + 2
    ch_info_opt_ind = int(wsmp_dump[_index:_index + 2], 16)
    _sequence.append(("ch_info_opt_ind", _index))
    _index = _index + 2
    ch_info_inst["operating_class"] = operating_class
    ch_info_inst["ch_num"] = ch_num
    ch_info_inst["tx_pwr_level"] = tx_pwr_level
    ch_info_inst["adaptable"] = adaptable
    ch_info_inst["data_rate"] = data_rate
    ch_info_inst["ch_info_opt_ind"] = ch_info_opt_ind
    #wsmp_dump = wsmp_dump[_index:]
    if ch_info_inst["ch_info_opt_ind"] & 1:
        wsmp_dump = cis_wave_info_elm_ext_dec(wsmp_dump)
    return wsmp_dump


def wsa_ch_info_seg_dec(wsmp_dump):
    global wsa_ch_info_seg
    global ch_info_inst
    global _sequence
    global _index
    ciscount = int(wsmp_dump[_index:_index + 2], 16)
    wsa_ch_info_seg["count"] = ciscount
    _sequence.append(("wsa_ch_info_seg_count", _index))
    _index += 2
    for cis_elm in range(wsa_ch_info_seg["count"]):
        wsmp_dump = ch_info_inst_dec(wsmp_dump)
        wsa_ch_info_seg["ch_info_inst"].append(
            copy.deepcopy(ch_info_inst))
    return wsmp_dump


def rout_wave_info_elm_ext_dec(wsmp_dump):
    global rout_wave_info_elm_ext
    global _sequence
    global _index
    count = int(wsmp_dump[_index:_index + 2], 16)
    rout_wave_info_elm_ext["count"] = count
    _sequence.append(("rout_wave_info_elm_ext_count", _index))
    _index += 2
    for routelm in range(rout_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[_index:_index + 2], 16)
        info_elm_name = Info_elm_Dict[info_elm_id]
        _sequence.append((info_elm_name, _index))
        _index += 2
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[_index:_index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        _sequence.append(("{}_elm_len".format(info_elm_name), _index))
        _index = _index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[_index:_index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        _sequence.append(("{}_elm_val".format(info_elm_name), _index))
        _index = _index + 2 * elm_len
        rout_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    return wsmp_dump


def wsa_routing_advt_dec(wsmp_dump):
    global wsa_routing_advt
    global rout_wave_info_elm_ext
    global _sequence
    global _index
    router_lifetime = wsmp_dump[_index:_index + 4]  # 2 octets length
    _sequence.append(("router_lifetime", _index))
    _index = _index + 4
    ip_prefix = wsmp_dump[_index:_index + 32]  # 16 octets length
    _sequence.append(("ip_prefix", _index))
    _index = _index + 32
    prefix_len = wsmp_dump[_index:_index + 2]  # 1 octet length
    _sequence.append(("prefix_len", _index))
    _index = _index + 2
    default_gateway = wsmp_dump[_index:_index + 32]  # 16 octet length
    _sequence.append(("default_gateway", _index))
    _index = _index + 32
    primary_dns = wsmp_dump[_index:_index + 32]  # 16 octet length
    _sequence.append(("primary_dns", _index))
    _index = _index + 32
    wsa_routing_advt["router_lifetime"] = int(router_lifetime, 16)
    wsa_routing_advt["ip_prefix"] = ip_prefix
    wsa_routing_advt["prefix_len"] = int(prefix_len, 16)
    wsa_routing_advt["default_gateway"] = default_gateway
    wsa_routing_advt["primary_dns"] = primary_dns
    wra_count = int(wsmp_dump[_index:_index + 2], 16)
    # There is no option indicator for routing advrt. So we are using
    # 'wra_count' as classifier
    _sequence.append(("wra_count", _index))
    _index += 2
    # wsmp_dump = wsmp_dump[_index:]
    if wra_count:
        wsmp_dump = rout_wave_info_elm_ext_dec(wsmp_dump)
    else:
        rout_wave_info_elm_ext["count"] = 0
        wsmp_dump = wsmp_dump[2:]
    return wsmp_dump


def wsa_head_dec(wsmp_dump):
    global wsa_head
    global _index
    global _sequence
    wsacode = int(wsmp_dump[_index:_index + 2], 16)
    wsa_head["version"] = (wsacode & 240) >> 4
    _sequence.append(("wsa_head_version", _index))
    wsa_head["opt_ind"] = (wsacode & 15)
    _sequence.append(("wsa_head_opt_ind", _index))
    _index += 2
    wsacode = int(wsmp_dump[_index:_index + 2], 16)
    wsa_head["wsa_id"] = (wsacode & 240) >> 4
    _sequence.append(("wsa_head_wsa_id", _index))
    wsa_head["cntnt_cnt"] = (wsacode & 15)
    _sequence.append(("wsa_head_cntnt_cnt", _index))
    _index += 2
    # wsmp_dump = wsmp_dump[_index:]
    if wsa_head["opt_ind"] & 8:
        wsmp_dump = wsa_head_info_elm_ext_dec(wsmp_dump)
    if wsa_head["opt_ind"] & 4:
        wsmp_dump = wsa_serv_info_seg_dec(wsmp_dump)
    if wsa_head["opt_ind"] & 2:
        wsmp_dump = wsa_ch_info_seg_dec(wsmp_dump)
    if wsa_head["opt_ind"] & 1:
        wsmp_dump = wsa_routing_advt_dec(wsmp_dump)
    return wsmp_dump


def lat_long_ele_conv():
    global wsa_head_info_elm_ext
    wsa_info_keys = wsa_head_info_elm_ext["info_elm"].keys()

    def three_dim_location_dec(elm_val):
        lat = (int(elm_val[0:8], 16) - 900000000) / 10000000
        lon = (int(elm_val[8:16], 16) - 1800000000) / 10000000
        try:
            elv = (int(elm_val[16:], 16) - 4096)
            return {"lat": lat, "lon": lon, "elv": elv}
        except IndexError:
            return {"lat": lat, "lon": lon}
    if "3d_location" in wsa_info_keys:
        location_dict = three_dim_location_dec(
            wsa_head_info_elm_ext["info_elm"]["3d_location"]["elm_val"])
        wsa_head_info_elm_ext["info_elm"]["3d_location"] = location_dict
    elif "2d_location" in wsa_info_keys:
        location_dict = three_dim_location_dec(
            wsa_head_info_elm_ext["info_elm"]["2d_location"]["elm_val"])
        wsa_head_info_elm_ext["info_elm"]["2d_location"] = location_dict


def random_hex_gen(num_val):
    hexvalues = ["0", "1", "2", "3", "4", "5", "6",
                 "7", "8", "9", "a", "b", "c", "d", "e", "f"]
    perms = list(itertools.permutations(hexvalues, 2))
    hex_vals = random.sample(perms, num_val // 2)
    hex_str = ""
    for val in hex_vals:
        hex_str += "".join(val)
    return hex_str


def pkt_logger(pkt, key):
    with open("{}/pktSimFiles/pktSimData.txt".format(_HOME), "w+") as pkt_file:
        timestamp = datetime.datetime.now().strftime("%b_%d_%I:%M:%S_%Y")
        pkt_file.write("{}_{}\n".format(timestamp, key))
        pkt_file.write("{}\n".format(pkt))
    return 1


def pkt_send_all(hexdump, sim_opt, seq, keys, pkt_sock):
    num_of_pkt = 10  # num of packets to send
    if sim_opt["num_of_pkt"]:
        num_of_pkt = sim_opt["num_of_pkt"]
    for num, (val1, val2) in enumerate(seq):
        key = keys[num]
        byte_len = val2 - val1
        if byte_len == 0:
            continue
        for _ in range(num_of_pkt):
            print(Fore.GREEN + key + Fore.BLACK)
            rand_val = random_hex_gen(byte_len)
            print(hexdump[:val1] + Fore.RED +
                  rand_val + Fore.BLACK + hexdump[val2:])
            pkt = hexdump[:val1] + rand_val + hexdump[val2:]
            if sim_opt["log"]:
                pkt_logger(pkt, key)
            sleep(1)
            pkt = str_to_bin(pkt)
            pkt_sock.sendto(pkt, ("10.0.0.229", 12189))
    return 1


def pktsend(hexdump, sim_opt, seq_dict):
    global _HOME
    print(seq_dict)
    pkt_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    values = [val for val in seq_dict.values()]
    keys = [val for val in seq_dict.keys()]
    seq = zip(values[:-1], values[1:])
    if sim_opt["field"]:
        field = sim_opt["field"]
        ind = keys.index(sim_opt["field"])
        num_of_pkt = 10  # num of packets to send
        if sim_opt["num_of_pkt"]:
            num_of_pkt = sim_opt["num_of_pkt"]
        val1 = values[ind]
        val2 = val1 + 2
        try:
            for v in values[ind + 1:]:
                if v == val1:
                    continue
                val2 = v
                break
        except UnboundLocalError:
            val2 = val1 + 2
        print(val1, val2)
        byte_len = val2 - val1
        for _ in range(num_of_pkt):
            print(Fore.GREEN + field + Fore.BLACK)
            rand_val = random_hex_gen(byte_len)
            print(hexdump[:val1] + Fore.RED +
                  rand_val + Fore.BLACK + hexdump[val2:])
            pkt = hexdump[:val1] + rand_val + hexdump[val2:]
            if sim_opt["log"]:
                pkt_logger(pkt)
            sleep(1)
            pkt = str_to_bin(pkt)
            pkt_sock.sendto(pkt, ("10.0.0.229", 12189))
        return 1
    pkt_send_all(hexdump, sim_opt, seq, keys, pkt_sock)
    return 1


def str_to_bin(code):
    byt_arr = bytearray()
    try:
        for byte in (code[j:j + 2] for j in range(0, len(code), 2)):
            byt_arr.append(int(byte, 16))
    except IndexError:
        print("End of code reached")
        return byt_arr
    return byt_arr


def parser():
    sim_opt = {
        "hexcode": None,
        "keys": None,
        "num_of_pkt": None,
        "log": None,
        "field": None
        # "sec": None,
        # "min": None,
        # "hour": None
    }
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-x", "--hexcode", help="Hexcode on which we have to simulate")
    parser.add_argument(
        "-k", "--keys", help="Wsmp pkt fields which we can modify")
    parser.add_argument(
        "-n", "--num_of_pkt", help="No of packets to send", type=int)
    parser.add_argument(
        "-l", "--logger", help="To log the generated packets")
    parser.add_argument(
        "-f", "--field_to_send", help="Use this option to change the"
        "specific field in hexcode")
    # parser.add_argument(
    #    "-t", "--time_in_sec",
    #    help="Num of sec simulator going to transmit the packets")
    # parser.add_argument(
    #    "-tm", "--time_in_min",
    #    help="Num of min simulator going to transmit the packets")
    # parser.add_argument(
    #    "-th", "--time_in_hour",
    #    help="Num of hour simulator going to transmit the packets")
    args = parser.parse_args()
    sim_opt["hex_code"] = args.hexcode
    sim_opt["keys"] = args.keys
    sim_opt["num_of_pkt"] = args.num_of_pkt
    sim_opt["log"] = args.logger
    sim_opt["field"] = args.field_to_send
    return sim_opt


if __name__ == "__main__":
    _set_env()
    sim_opt = parser()
    if sim_opt["hexcode"]:
        wsmp_pkt = sim_opt["hexcode"]
    else:
        print("wsmppkt not provided.\nUsing the default packet\n")
        print(_hexdump_deflt)
        print("\n")
        wsmp_pkt = _hexdump_deflt
    wsmp_head_init()
    wsmp_head_dec(wsmp_pkt)
    wsa_head_dec(
        wsmp_pkt) if T_head["PSID"] == 0x8007 else print()
    seq_dict = OrderedDict(_sequence)
    if sim_opt["keys"]:
        print(list(seq_dict.keys()))
        exit(0)
    pktsend(wsmp_pkt, sim_opt, seq_dict)
