'''
    File name: libRSE.py
    Author: Ravi Teja Nagamothu
    Date created: 20/02/2018
    Python Version: 3.6
'''
import re
import copy
import sys
import json
import config
from functools import reduce
import os
from time import sleep


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
security_hdr=None
signed_data=None
tbs_data=None
secure_hdr_data=None
security_hdr_content=None
security_trailer_header_info=None
signer_info=None
certificate_info=None
to_be_signed=None
verify_key_indicator=None
signature=None
signed_data=None
wsm_security_trailer=None


def wsmp_head_init():
    global SECURED, UNSECURED, Info_elm_Dict_def, wave_info_elm_ext
    global security_hdr,signed_data,tbs_data,secure_hdr_data,security_hdr_content,security_trailer_header_info,\
        signer_info,certificate_info,to_be_signed,verify_key_indicator,signature,signed_data,wsm_security_trailer
    global N_head, info_elm, T_head, wsa_head_info_elm_ext, wsa_head
    global sis_wave_info_elm_ext, serv_info_inst, wsa_serv_info_seg
    global cis_wave_info_elm_ext, ch_info_inst, wsa_ch_info_seg
    global rout_wave_info_elm_ext, wsa_routing_advt, wsa, wsm, wsm_data, wsmp
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
        "security_hdr":None
    }

    security_hdr = {
        "protocol_version" : None, # 1 byte
        "choice tag": None, # 4 bits
        "content": None, # 4 bits
        "signed_data":signed_data
    }
    signed_data={
        "hashID":None, # 1 byte 0==SHA256
        "tbs_data":tbs_data
    }
    tbs_data={
        "extension_bit":None, # first bit in after payload first byte
        "optional field bit for data":None,# second bit in after payload first byte
        "optional field bit for extdHash":None, # third bit to end in after payload first byte
        "data":secure_hdr_data
    }

    secure_hdr_data={
        "protocol_version":None, # 1 byte
        "choice tag":None, # 1st or 2nd bit in next byte
        "content":security_hdr_content
    }
    security_hdr_content={
    "payload_length":None,# 1 byte
    "unsecured_data":None,# based on payload length
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
    wsm = {
        "unsecure_payload": None
    }
    wsm_data = {
        "wsa": wsa,
        "wsm": wsm
    }

    security_trailer_header_info= {
        "Extension_bit": None, # first bit in next byte
        "generation_time_present":None,# 2nd bit in next byte
        "Expiry_time_is_present":None,# 3rd bit in next byte
        "generation_location_present":None,# 4th bit in next byte
        "p2pcd_learning_request":None,# 5th bit in next byte
        "missing_crl_identifier":None,# 6th bit in next byte
        "encryption_key":None,# 7th bit in next byte
        "integer_length":None,# 1 byte
        "psid":None,# 2 bytes
        "generation_time":None,# 4 bytes
        "expiry_time":None,# 4 bytes
        "generation_location":{
            "lat":None, # 8 bytes
            "lon":None ,# 8 bytes
            "elv":None # 4 bytes
        },
        "choice_tag":None # 1 byte
    }

    signer_info={
        "signer": None, # 4 bits
        "sequence_of_length":None,# 2 bytes
        "certificate":certificate_info
    }
    certificate_info={
        "signature_is_not_present":None,# 1 byte first bit in next byte
        "version":None,# 1 byte
        "Extension_present_bit":None, # 1 byte first bit in next byte
        "choice tag":None, # 1 byte
        "sha256_and_digest":None, # 8 bytes
        "toBesigned":to_be_signed
    }

    to_be_signed={
        "Extension_bit":None,# 1st bit in next byte
        "region":None,# 2nd bit in next byte
        "assurance_level":None,# 3rd bit in next byte
        "app_permissionOf":None,# 4th bit in next byte
        "certIssuePermissions":None,# 5th bit in next byte
        "certRequestpermissions":None,# 6th bit in next byte
        "canRequestRollover":None,# 7th bit in next byte
        "encryption_key":None,# 8th bit in next byte
        "choice_tag":None,# 1 byte
        "linkage_data":None,  # 1st bit in next byte
        "iCert":None, # 2 bytes
        "linkage_value":None, # 9 bytes
        "cracaid":None, #3 bytes
        "crlSeries":None, #2 bytes
        "Validity_period_start":None,#4bytes
        "Validity_period_duration":None, #3 bytes
        "Validity_period_assurance_level":None,#1 byte
        "sequence_of_length":None,#2 bytes
        "app_permissions_ssp_present":None,# 1st bit in next byte
        "integer length":None,# 1 byte
        "PSID":None,#1 byte
        "app_permissions_choice_tag":None,#1 byte
        "ssp_len":None,#1 byte
        "app_pemissionsOf_choice_tag":None,#1 byte
        "verify_key_indicator":verify_key_indicator
    }

    verify_key_indicator={
        "choice_tag":None,#1 byte
        "compressed_y_1":None,#32 bytes
        "verify_key_indicator_choice_tag":None #1 byte
    }
    signature={
        "signature": None, # 4 bits
        "choice_tag":None, # 4 bits
        "r": None, # 4 bits
        "Compressed_y_1":None, #32 bytes
        "s":None,# 32 bytes

    }
    wsm_security_trailer={
        "security_trailer_header_info":security_trailer_header_info ,
       "security signer info":signer_info,
        "signature":signature
    }
    wsmp = {
        "N-head": N_head,
        "T-head": T_head,
        "wsm_data": wsm_data ,
        "wsm_security_trailer":wsm_security_trailer
    }
    return 1


def wsmp_head_dec(wsmp_dump):
    wsmp_dump = wsmp_n_head_dec(wsmp_dump)
    wsmp_dump = wsmp_t_head_dec(wsmp_dump)
    wsmp_dump = wsmp_payload_dec(wsmp_dump)
    return wsmp_dump


def wsmp_n_head_dec(wsmp_dump):
    global N_head
    hex_code = int(wsmp_dump[0:2], 16)
    N_head["subtype"] = (hex_code & 240) >> 4
    opt_ind = (hex_code & 8) >> 3  # opt ind is one bit size
    N_head["opt_ind"] = opt_ind
    N_head["version"] = hex_code & 7
    wsmp_dump = wsmp_dump[2:]
    if N_head["opt_ind"]:
        wsmp_dump = wave_info_elm_ext_dec(wsmp_dump)
        N_head["TPID"] = int(wsmp_dump[0:2], 16)
        wsmp_dump = wsmp_dump[2:]
        return wsmp_dump
    else:
        N_head["TPID"] = int(wsmp_dump[0:2], 16)
        wsmp_dump = wsmp_dump[2:]
        return wsmp_dump


def wave_info_elm_ext_dec(wsmp_dump):
    global wave_info_elm_ext
    global Info_elm_Dict_def
    global Info_elm_Dict
    wave_info_elm_ext["count"] = int(wsmp_dump[0:2], 16)
    wsmp_dump = wsmp_dump[2:]
    index = 0
    for elm in range(wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[index:index + 2], 16)
        index = index + 2
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[index:index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        index = index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[index:index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        index = index + 2 * elm_len
        wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    return wsmp_dump


def wsmp_t_head_dec(wsmp_dump):
    global T_head

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
        if sec_head_pos:
            global SECURED
            SECURED = 1
            T_head["secured"] = SECURED
            wsm_len_octets = sec_head_pos.start() // 2
            return wsm_len_octets
        else:
            global UNSECURED
            UNSECURED = 1
            T_head["unsecured"] = UNSECURED
            wsm_len_octets = unsec_head_pos.start() // 2
            return wsm_len_octets
    psid_len = psid_len_calc(wsmp_dump[0])
    T_head["PSID"] = int(wsmp_dump[:psid_len * 2], 16)
    wsmp_dump = wsmp_dump[psid_len * 2:]
    sec_head_pos = re.search("03810040", wsmp_dump)
    unsec_head_pos = re.search("0380", wsmp_dump)
    wsm_len_octets = wsm_len_calc(wsmp_dump, sec_head_pos,
                                  unsec_head_pos)
    wsm_len_val = int(wsmp_dump[:wsm_len_octets * 2], 16)
    security_header_start=wsmp_dump[wsm_len_octets * 2:unsec_head_pos.end()]
    if wsm_len_val < 128:
        T_head["wsm_len_before"] = wsm_len_val
    else:
        T_head["wsm_len_before"] = wsm_len_val - 32768
    wsmp_dump = wsmp_dump[unsec_head_pos.end():]
    if T_head["PSID"] == 0x8007:
        wsa_len_val = int(wsmp_dump[:2], 16)
        if wsa_len_val < 128:
            T_head["wsm_len_after"] = wsa_len_val
            security_offset=wsmp_dump[:2]
            wsmp_dump = wsmp_dump[2:]
        else:
            wsa_len_val = int(wsmp_dump[:4], 16)
            T_head["wsm_len_after"] = wsa_len_val - 32896
            security_offset=wsmp_dump[:4]
            wsmp_dump = wsmp_dump[4:]
    else:
        wsa_len_val = int(wsmp_dump[:2], 16)
        if wsa_len_val <= 128:
            T_head["wsm_len_after"] = wsa_len_val
            wsmp_dump = wsmp_dump[2:]
        elif wsa_len_val == 129:
            T_head["wsm_len_after"] = int(wsmp_dump[2:4], 16)
            wsmp_dump = wsmp_dump[4:]
        elif wsa_len_val == 130:
            T_head["wsm_len_after"] = int(wsmp_dump[2:6], 16)
            wsmp_dump = wsmp_dump[6:]

    if T_head["secured"]:
        wsm_security_header_decoder(security_header_start+security_offset,wsmp_dump)
    else:
        print("Not secured packet")
    return wsmp_dump


def wsmp_payload_dec(wsmp_dump):
    """ Author : Manasa Dosapati """
    global wsm
    global wmsp_t_head_dec
    wsmp_payload_len = T_head["wsm_len_after"]
    wsm["unsecure_payload"] = wsmp_dump[:wsmp_payload_len * 2]
    return wsmp_dump


def wsm_security_header_decoder(security_dump,wsmp_dump):

    # def calc_payload_len(data):
    #     if int(data[0:2], 16) == 128:
    #         return 1
    #     elif int(data[2:4], 16) == 128:
    #         return 2
    #     elif int(data[4:6], 16) == 128:
    #         return 3
    #     elif int(data[6:8], 16) == 128:
    #         return 4
    #     else:
    #         return -1

    security_hdr["protocol_version"]=int(security_dump[0:2],16)
    choice_tag=int(security_dump[2:3],16)
    #choice_tag=(choice_tag & 192) >> 6
    security_hdr["content"] = int(security_dump[3:4],16)
    security_hdr["choice tag"]=choice_tag
    if int(security_dump[4:6],16)==0:
        signed_data["hashID"]="sha256"
    else:
        signed_data["hashID"]=int(security_dump[4:6],16)
    extn_bit_calc=int(security_dump[6:8],16)
    extn_bit_flag=(extn_bit_calc & 128) >> 7
    data_bit_flag=(extn_bit_calc & 64) >> 6
    extDataHash_bit_flag=(extn_bit_calc & 32) >> 5

    # if extn_bit_flag:
    #     tbs_data["extension_bit"]="True"
    # else:
    #     tbs_data["extension_bit"] = "False"
    # if data_bit_flag:
    #     tbs_data["optional field bit for data"]="True"
    # else:
    #     tbs_data["optional field bit for data"] = "False"
    # if extDataHash_bit_flag:
    #     tbs_data["optional field bit for extdHash"]="True"
    # else:
    #     tbs_data["optional field bit for extdHash"] = "False"
    tbs_data["extension_bit"]=extn_bit_flag
    tbs_data["optional field bit for data"]=data_bit_flag
    tbs_data["optional field bit for extdHash"]=extDataHash_bit_flag
    secure_hdr_data["protocol_version"]=int(security_dump[8:10],16)
    secure_hdr_data["choice tag"]=(int(security_dump[10:12],16) & 192) >> 6
    if int(security_dump[12:14],16)<128:
        security_hdr_content["payload_length"]=int(security_dump[12:14],16)
    elif int(security_dump[12:14],16)==128:
        security_hdr_content["payload_length"] = int(security_dump[14:16], 16)
    else:
        pay_load_len=int(security_dump[12:14],16) & 15
        security_hdr_content["payload_length"]=int(security_dump[14:14+pay_load_len*2], 16)
    security_hdr_content["unsecured_data"]=wsmp_dump[:security_hdr_content["payload_length"]*2]
    secure_hdr_data["content"]=security_hdr_content
    tbs_data["data"]=secure_hdr_data
    signed_data["tbs_data"]=tbs_data
    security_hdr["signed_data"] = signed_data
    # print(security_hdr)
    T_head["security_hdr"]=security_hdr
    return security_dump


def wsa_head_info_elm_ext_dec(wsmp_dump):
    global wsa_head_info_elm_ext
    global Info_elm_Dict_def
    global Info_elm_Dict
    wsacode = int(wsmp_dump[0:2], 16)
    wsmp_dump = wsmp_dump[2:]
    wsa_head_info_elm_ext["count"] = wsacode
    index = 0
    for elm in range(wsa_head_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[index:index + 2], 16)
        index = index + 2
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[index:index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        index = index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[index:index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        index = index + 2 * elm_len
        wsa_head_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    lat_long_ele_conv()
    return wsmp_dump


def ch_info_inst_get(PSID, option, sub_option=''):
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
        if re.search(r"^count$", option):
            return wsa_ch_info_seg[option]
        ch_info_data = \
            wsa_ch_info_seg["ch_info_inst"][ch_index[0] - 1]
        if option in ch_info_data:
            value = ch_info_data[option]
            return value if value is not None else "-1"
        if ch_info_data["ch_info_opt_ind"] == 1:
            ch_info_data = ch_info_data["cis_wave_info_elm_ext"]
            if re.search(r"^cis_wave_info_elm_ext_count$", option):
                return ch_info_data["count"]

            elif ch_info_data["count"] > 1 and option in list(ch_info_data['info_elm'].keys()):
                return ch_info_data['info_elm'][option][sub_option]

            else:
                return "-1"
        else:
            return "-1"

    except IndexError:
        return "-1"
    except KeyError:
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
    elmcnt = int(wsmp_dump[:2], 16)
    sis_wave_info_elm_ext["count"] = elmcnt
    wsmp_dump = wsmp_dump[2:]
    index = 0
    for elm in range(sis_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[index:index + 2], 16)
        index = index + 2
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[index:index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        index = index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[index:index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        index = index + 2 * elm_len
        sis_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    return wsmp_dump


def serv_info_inst_dec(wsmp_dump):
    global sis_wave_info_elm_ext
    global serv_info_inst

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
    psid_len = psid_len_calc(wsmp_dump[0])
    psid = int(wsmp_dump[:psid_len * 2], 16)
    serv_info_inst["PSID"] = psid
    wsmp_dump = wsmp_dump[psid_len * 2:]
    siscode = int(wsmp_dump[:2], 16)
    wsmp_dump = wsmp_dump[2:]
    serv_info_inst["ch_ind"] = (siscode & 248) >> 3  # 5 bits
    serv_info_inst["reserved"] = (siscode & 6) >> 1  # 2 bits
    serv_info_inst["opt_in"] = (siscode & 1)  # 1 bit
    if serv_info_inst["opt_in"]:
        wsmp_dump = sis_wave_info_elm_ext_dec(wsmp_dump)
    return wsmp_dump


def wsa_serv_info_seg_dec(wsmp_dump):
    global wsa_serv_info_seg
    global serv_info_inst
    siscount = int(wsmp_dump[:2], 16)
    wsmp_dump = wsmp_dump[2:]
    wsa_serv_info_seg["count"] = siscount
    for sis_elm in range(wsa_serv_info_seg["count"]):
        wsmp_dump = serv_info_inst_dec(wsmp_dump)
        wsa_serv_info_seg["serv_info_inst"].append(
            copy.deepcopy(serv_info_inst))
    return wsmp_dump


def cis_wave_info_elm_ext_dec(wsmp_dump):
    global cis_wave_info_elm_ext
    count = int(wsmp_dump[:2], 16)
    cis_wave_info_elm_ext["count"] = count
    wsmp_dump = wsmp_dump[2:]
    index = 0
    for ciselm in range(cis_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[index:index + 2], 16)
        index = index + 2
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[index:index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        index = index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[index:index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        index = index + 2 * elm_len
        cis_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    return wsmp_dump


def ch_info_inst_dec(wsmp_dump):
    global ch_info_inst
    global cis_wave_info_elm_ext
    index = 0
    operating_class = int(wsmp_dump[index:index + 2], 16)
    index = index + 2
    ch_num = int(wsmp_dump[index:index + 2], 16)
    index = index + 2
    tx_pwr_level = int(wsmp_dump[index:index + 2], 16)
    index = index + 2
    adaptable = (int(wsmp_dump[index:index + 2], 16) & 128) >> 7
    data_rate = (int(wsmp_dump[index:index + 2], 16) & 127)
    index = index + 2
    ch_info_opt_ind = int(wsmp_dump[index:index + 2], 16)
    index = index + 2
    ch_info_inst["operating_class"] = operating_class
    ch_info_inst["ch_num"] = ch_num
    ch_info_inst["tx_pwr_level"] = tx_pwr_level
    ch_info_inst["adaptable"] = adaptable
    ch_info_inst["data_rate"] = data_rate
    ch_info_inst["ch_info_opt_ind"] = ch_info_opt_ind
    wsmp_dump = wsmp_dump[index:]
    if ch_info_inst["ch_info_opt_ind"] & 1:
        wsmp_dump = cis_wave_info_elm_ext_dec(wsmp_dump)
    return wsmp_dump


def wsa_ch_info_seg_dec(wsmp_dump):
    global wsa_ch_info_seg
    global ch_info_inst
    ciscount = int(wsmp_dump[:2], 16)
    wsmp_dump = wsmp_dump[2:]
    wsa_ch_info_seg["count"] = ciscount
    for cis_elm in range(wsa_ch_info_seg["count"]):
        wsmp_dump = ch_info_inst_dec(wsmp_dump)
        wsa_ch_info_seg["ch_info_inst"].append(
            copy.deepcopy(ch_info_inst))
    return wsmp_dump


def rout_wave_info_elm_ext_dec(wsmp_dump):
    global rout_wave_info_elm_ext
    count = int(wsmp_dump[:2], 16)
    rout_wave_info_elm_ext["count"] = count
    wsmp_dump = wsmp_dump[2:]
    index = 0
    for routelm in range(rout_wave_info_elm_ext["count"]):
        info_elm_id = int(wsmp_dump[index:index + 2], 16)
        index = index + 2
        info_elm_name = Info_elm_Dict[info_elm_id]
        Info_elm_Dict_def[info_elm_name]["elm_id"] = info_elm_id
        elm_len = int(wsmp_dump[index:index + 2], 16)
        Info_elm_Dict_def[info_elm_name]["elm_len"] = elm_len
        index = index + 2
        Info_elm_Dict_def[info_elm_name]["elm_val"] = wsmp_dump[index:index +
                                                                (2 * elm_len)]
        # Multiplying with two because one hex value requires two chr.
        # But to get the actual len of str we need to multiply with two.
        index = index + 2 * elm_len
        rout_wave_info_elm_ext["info_elm"][info_elm_name] = Info_elm_Dict_def[
            info_elm_name]
    wsmp_dump = wsmp_dump[index:]
    return wsmp_dump


def wsa_routing_advt_dec(wsmp_dump):
    global wsa_routing_advt
    global rout_wave_info_elm_ext
    index = 0
    router_lifetime = wsmp_dump[index:index + 4]  # 2 octets length
    index = index + 4
    ip_prefix = wsmp_dump[index:index + 32]  # 16 octets length
    index = index + 32
    prefix_len = wsmp_dump[index:index + 2]  # 1 octet length
    index = index + 2
    default_gateway = wsmp_dump[index:index + 32]  # 16 octet length
    index = index + 32
    primary_dns = wsmp_dump[index:index + 32]  # 16 octet length
    index = index + 32
    wsa_routing_advt["router_lifetime"] = int(router_lifetime, 16)
    wsa_routing_advt["ip_prefix"] = ip_prefix
    wsa_routing_advt["prefix_len"] = int(prefix_len, 16)
    wsa_routing_advt["default_gateway"] = default_gateway
    wsa_routing_advt["primary_dns"] = primary_dns
    wra_count = int(wsmp_dump[index:index + 2], 16)
    # There is no option indicator for routing advrt. So we are using
    # 'wra_count' as classifier
    wsmp_dump = wsmp_dump[index:]
    if wra_count:
        wsmp_dump = rout_wave_info_elm_ext_dec(wsmp_dump)
    else:
        rout_wave_info_elm_ext["count"] = 0
        wsmp_dump = wsmp_dump[2:]
    return wsmp_dump


def wsa_head_dec(wsmp_dump):
    global wsa_head
    wsacode = int(wsmp_dump[0:2], 16)
    wsmp_dump = wsmp_dump[2:]
    wsa_head["version"] = (wsacode & 240) >> 4
    wsa_head["opt_ind"] = (wsacode & 15)
    wsacode = int(wsmp_dump[0:2], 16)
    wsmp_dump = wsmp_dump[2:]
    wsa_head["wsa_id"] = (wsacode & 240) >> 4
    wsa_head["cntnt_cnt"] = (wsacode & 15)
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
            try:
                elv = (int(elm_val[16:], 16) - 4096)
            except ValueError:
                print("2D FIX")
                elv = None
            return {"lat": lat, "lon": lon, "elv": elv}
        except IndexError:
            return {"lat": lat, "lon": lon}
    if "3d_location" in wsa_info_keys:
        location_dict = three_dim_location_dec(
            wsa_head_info_elm_ext["info_elm"]["3d_location"]["elm_val"])
        wsa_head_info_elm_ext["info_elm"]["3d_location"] = location_dict
        wsa_head_info_elm_ext["info_elm"]["lat"] = location_dict["lat"]
        wsa_head_info_elm_ext["info_elm"]["lon"] = location_dict["lon"]
        wsa_head_info_elm_ext["info_elm"]["elv"] = location_dict["elv"]

        # wsa_head_info_elm_ext["info_elm"]["2d_location"] = {"lat": None, "lon": None}

    elif "2d_location" in wsa_info_keys:
        location_dict = three_dim_location_dec(
            wsa_head_info_elm_ext["info_elm"]["2d_location"]["elm_val"])
        wsa_head_info_elm_ext["info_elm"]["2d_location"] = location_dict
        wsa_head_info_elm_ext["info_elm"]["lat"] = location_dict["lat"]
        wsa_head_info_elm_ext["info_elm"]["lon"] = location_dict["lon"]
        wsa_head_info_elm_ext["info_elm"]["elv"] = None
    else:
        wsa_head_info_elm_ext["info_elm"]["lat"] = None
        wsa_head_info_elm_ext["info_elm"]["lon"] = None
        wsa_head_info_elm_ext["info_elm"]["elv"] = None


def wsm_security_trailer_dec(wsmp_dump):
    print(wsmp_dump)
    extension_bit_flags=int(wsmp_dump[:2],16)
    # print(extension_bit_flags)
    security_trailer_header_info["Extension_bit"] = (extension_bit_flags & 128) >> 7
    security_trailer_header_info["generation_time_present"] = (extension_bit_flags & 64) >> 6
    security_trailer_header_info["Expiry_time_is_present"] = (extension_bit_flags & 32) >> 5
    security_trailer_header_info["generation_location_present"]= (extension_bit_flags & 16) >> 4
    security_trailer_header_info["p2pcd_learning_request"]= (extension_bit_flags & 8)
    security_trailer_header_info["missing_crl_identifier"]= (extension_bit_flags & 4)
    security_trailer_header_info["encryption_key"] = (extension_bit_flags & 2)
    psid_length=int(wsmp_dump[2:4],16)
    security_trailer_header_info["integer_length"] = psid_length
    security_trailer_header_info["psid"] = int(wsmp_dump[4:4+(psid_length)*2],16)
    wsmp_dump=wsmp_dump[4+psid_length*2:]
    if security_trailer_header_info["generation_time_present"]:
        security_trailer_header_info["generation_time"]=int(wsmp_dump[:16],16)
        wsmp_dump=wsmp_dump[16:]
    if security_trailer_header_info["Expiry_time_is_present"]:
        security_trailer_header_info["expiry_time"]=int(wsmp_dump[:16],16)
        wsmp_dump=wsmp_dump[16:]
    if security_trailer_header_info["generation_location_present"]:
        # lat = (int(wsmp_dump[0:8],16) - 900000000) / 10000000
        # lon = (int(wsmp_dump[8:16],16) - 1800000000) / 10000000
        # elv = (int(wsmp_dump[16:20],16) - 4096)
        security_trailer_header_info["generation_location"]["lat"]=int(wsmp_dump[0:8],16)
        security_trailer_header_info["generation_location"]["lon"]=int(wsmp_dump[8:16],16)
        security_trailer_header_info["generation_location"]["elv"]=int(wsmp_dump[16:20],16)
        # security_trailer_header_info["generation_location"]["lat"]=lat
        # security_trailer_header_info["generation_location"]["lon"]=lon
        # security_trailer_header_info["generation_location"]["elv"]=elv
        wsmp_dump=wsmp_dump[20:]
    security_trailer_header_info["choice_tag"]=int(wsmp_dump[0:1],16)
    signer_info["signer"]=int(wsmp_dump[1:2],16)
    # signer_info["signer"]=int(wsmp_dump[2:4],16)
    signer_info["sequence_of_length"]=int(wsmp_dump[2:6],16)
    certificate_info["signature_is_not_present"]=(int(wsmp_dump[6:8],16) & 127 >> 7)
    certificate_info["version"]= int(wsmp_dump[8:10],16)
    certificate_info["Extension_present_bit"]=(int(wsmp_dump[10:12],16) & 127 >> 7)
    certificate_info["choice tag"]=int(wsmp_dump[12:14],16)
    certificate_info["sha256_and_digest"]=wsmp_dump[14:30]
    extension_bit_flags=int(wsmp_dump[30:32],16)
    to_be_signed["Extension_bit"] = (extension_bit_flags & 128) >> 7
    to_be_signed["region"] = (extension_bit_flags & 64) >> 6
    to_be_signed["assurance_level"] = (extension_bit_flags & 32) >> 5
    to_be_signed["app_permissionOf"]= (extension_bit_flags & 16) >> 4
    to_be_signed["certIssuePermissions"]= (extension_bit_flags & 8)
    to_be_signed["certRequestpermissions"]= (extension_bit_flags & 4)
    to_be_signed["canRequestRollover"] = (extension_bit_flags & 2)
    to_be_signed["encryption_key"] = (extension_bit_flags & 1)
    to_be_signed["choice_tag"]= int(wsmp_dump[32:34],16)
    to_be_signed["linkage_data"] =(int(wsmp_dump[34:36],16) & 127 >> 7)
    to_be_signed["iCert"]=int(wsmp_dump[36:40],16)
    to_be_signed["linkage_value"]=wsmp_dump[40:58]
    to_be_signed["cracaid"] = wsmp_dump[58:64]
    to_be_signed["crlSeries"]=int(wsmp_dump[64:68],16)
    to_be_signed["Validity_period_start"]=int(wsmp_dump[68:76],16)
    # choice tag
    to_be_signed["Validity_period_duration"]=int(wsmp_dump[78:82],16)
    to_be_signed["Validity_period_assurance_level"]=int(wsmp_dump[82:84],16)
    to_be_signed["sequence_of_length"] = int(wsmp_dump[84:88],16)
    to_be_signed["app_permissions_ssp_present"]=(int(wsmp_dump[88:90],16) & 127 >> 7)
    psid_length=int(wsmp_dump[90:92],16)
    to_be_signed["integer length"] = psid_length
    to_be_signed["PSID"] = int(wsmp_dump[92:92+(psid_length)*2],16)
    wsmp_dump=wsmp_dump[92+psid_length*2:]
    to_be_signed["app_permissions_choice_tag"]=int(wsmp_dump[0:2],16)
    to_be_signed["ssp_len"]=int(wsmp_dump[2:4],16)
    to_be_signed["app_pemissionsOf_choice_tag"]= int(wsmp_dump[4:6],16)
    verify_key_indicator["choice_tag"]=int(wsmp_dump[6:8],16)
    verify_key_indicator["compressed_y_1"]=wsmp_dump[8:72]
    verify_key_indicator["verify_key_indicator_choice_tag"]=int(wsmp_dump[72:73],16)
    signature["signature"]=int(wsmp_dump[73:74],16)    
    signature["choice_tag"]=int(wsmp_dump[74:75],16)
    signature["r"]=int(wsmp_dump[75:76],16)    
    signature["Compressed_y_1"]=wsmp_dump[76:140]
    signature["s"]=wsmp_dump[140:204]
    to_be_signed["verify_key_indicator"]=verify_key_indicator
    certificate_info["toBesigned"]=to_be_signed
    signer_info["certificate"]=certificate_info
    wsmp_dump=wsmp_dump[204:]
    print(wsmp_dump)
    return wsmp_dump
    

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Provide enough arguments")
        print("Usage:Python wsmpHead.py <hexdump>")
        exit(0)
    wsmp_head_init()
    hexdump = sys.argv[1]
    hexdump = re.sub(r"\s+", "", hexdump)
    llc_head = "88dc"
    llc_head_pos = re.search(llc_head, hexdump[:10])
    wsmp_dump = None
    if llc_head_pos:
        llc_head_pos_end = llc_head_pos.end()
        wsmp_dump = hexdump[llc_head_pos_end:]
    else:
        wsmp_dump = hexdump
    wsmp_dump = wsmp_head_dec(wsmp_dump)
    wsmp_dump = wsa_head_dec(
        wsmp_dump) if T_head["PSID"] == 0x8007 else print()
    wsmp_dump = wsm_security_trailer_dec(
        wsmp_dump) if T_head["secured"] else print()
    print("wsmp")
    print(json.dumps(wsmp, indent=2))
