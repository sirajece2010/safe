# -*- coding: utf-8 -*-
'''
    File name: etsihead.py
    Author: Dosapati Manasa
    Date created: 11/04/2018
    Python Version: 3.6
'''
import json
import sys
import re

# GN_Header dict
SECURED = None
UNSECURED = None
basic_hdr = None
B_NH = None
LT = None
flags_mob = None
mob_stationary = None
common_hdr = None
C_NH = None
HT = None
HST = None
TC = None
ext_hdr = None
lpv = None
spv = None
gn_addr = None
beacon_pkt_hdr = None
tsb_pkt_hdr = None
shb_pkt_hdr = None
gbc_pkt_hdr = None
gn_hdr = None
btp_hdr = None


def gn_hdr_init():
    global gn_hdr
    global beacon_pkt_hdr, tsb_pkt_hdr, shb_pkt_hdr, gbc_pkt_hdr
    global basic_hdr, LT
    global common_hdr, TC, flags_mob, mob_stationary
    global ext_hdr, lpv, spv, gn_addr
    global btp_hdr
    mob_stationary = {
        "stationary": None,
        "mobile": None
    }
    B_NH = {
        "B_NH_any": None,
        "common_hdr": None,
        "secured_pkt": None
    }
    LT = {
        "multiplier": None,  # 6 bits
        "base": None  # 2 bits
    }
    C_NH = {
        "C_NH_any": None,
        "btp_a": None,
        "btp_b": None,
        "ipv6": None
    }
    HT = {
        "HT_any": None,
        "beacon": None,
        "guc": None,
        "gac": None,
        "gbc": None,
        "tsb": None,
        "ls": None
    }
    HST = {
        "unspecified": None,
        "gac_circle": None,
        "gac_rect": None,
        "gac_elip": None,
        "gbc_circle": None,
        "gbc_rect": None,
        "gbc_elip": None,
        "single_hop": None,
        "multi_hop": None,
        "ls_request": None,
        "ls_reply": None
    }
    TC = {
        "scf": None,  # 1 bit
        "channel_offload": None,  # 1 bit
        "tc_id": None,  # 6 bits
    }
    flags_mob = {
        "gnsismobile": mob_stationary,  # 1 bit
        "flags_reserved": None  # 7 bits
    }
    gn_addr = {
        "manual_addr_conf": None,  # 1 bit
        "station_type": None,  # 5 bits
        "station_country_code": None,  # 10 bits
        "MID": None,  # 48 bits
    }
    lpv = {
        "so_gn_addr": gn_addr,  # 64 bits
        "so_tst": None,  # 32 bits
        "so_lat": None,  # 32 bits
        "so_long": None,  # 32 bits
        "pai": None,  # 1 bit
        "speed": None,  # 15 bits
        "heading": None,  # 16 bits
    }
    spv = {
        "de_gn_addr": None,  # 64 bits
        "de_tst": None,  # 32 bits
        "de_lat": None,  # 32 bits
        "de_long": None,  # 32 bits
    }
    shb_pkt_hdr = {
        "so_pv": None,
        "shb_reserved": None
    }
    beacon_pkt_hdr = {
        "so_pv": None  # 24 bytes
    }
    tsb_pkt_hdr = {
        "sequence_number": None,  # 2 bytes
        "tsb_reserved": None,  # 2 bytes
        "so_pv": None  # 24 bytes
    }
    gbc_pkt_hdr = {
        "sequence_number": None,  # 16 bits
        "gbc_reserved1": None,  # 16 bits
        "so_pv": None,  # 24 bytes
        "geo_area_pos_lat": None,  # 32 bits
        "geo_area_pos_long": None,  # 32 bits
        "dist_a": None,  # 32 bits
        "dist_b": None,  # 32 bits
        "angle": None,  # 16 bits
        "gbc_reserved2": None  # 16 bits
    }
    basic_hdr = {
        "version": None,  # 4 bits
        "basic_next_header": B_NH,  # 4 bits
        "basic_reserved": None,  # 8 bits
        "lifetime": LT,  # 8 bits
        "RHL": None  # 8 bits
    }
    common_hdr = {
        "common_next_header": C_NH,  # 4 bits
        "common_reserved1": None,  # 4 bits
        "header_type": HT,  # 4 bits
        "header_sub_type": HST,  # 4 bits
        "traffic_class": TC,  # 8 bits
        "flags": flags_mob,  # 8 bits
        "payload_length": None,  # 16 bits
        "max_hoplimit": None,  # 8 bits
        "common_reserved2": None  # 8 bits
    }
    ext_hdr = {
        "guc_pkt": None,
        "tsb_pkt": None,
        "shb_pkt": None,
        "gbc_pkt": None,
        "beacon_pkt": None,
        "ls_req_pkt": None,
        "ls_reply_pkt": None
    }
    btp_hdr = {
        "dest_port": None,  # 16 bytes
        "dest_port_info": None  # 16 bytes
    }
    gn_hdr = {
        "basic_header": basic_hdr,  # 4 bytes
        "common_header": common_hdr,  # 8 bytes
        "extended_header": ext_hdr  # variable bytes based on Header Type
    }
    return 1


def redirecting_api(etsi_dump):
    if common_hdr["header_type"] == 5 and common_hdr["header_sub_type"] == 0:
        etsi_dump = shb_pkt_hdr_dec(etsi_dump)
        ext_hdr["shb_pkt"] = shb_pkt_hdr
        return etsi_dump
    elif common_hdr["header_type"] == 1 and common_hdr["header_sub_type"] == 0:
        etsi_dump = beacon_pkt_hdr_dec(etsi_dump)
        ext_hdr["beacon_pkt"] = beacon_pkt_hdr
        return etsi_dump
    elif common_hdr["header_type"] == 4 and common_hdr["header_sub_type"] == 0 \
            or common_hdr["header_sub_type"] == 1 \
            or common_hdr["header_sub_type"] == 2:
        etsi_dump = gbc_pkt_hdr_dec(etsi_dump)
        ext_hdr["gbc_pkt"] = gbc_pkt_hdr
        return etsi_dump
    else:
        return etsi_dump


def gn_hdr_dec(etsi_dump):
    etsi_dump = basic_hdr_dec(etsi_dump)
    etsi_dump = common_hdr_dec(etsi_dump)
    return etsi_dump


def basic_hdr_dec(etsi_dump):
    global basic_hdr
    hex_code = int(etsi_dump[0:2], 16)
    basic_hdr["version"] = (hex_code & 240) >> 4
    B_NH_bits = (hex_code & 15)
    basic_hdr["basic_next_header"] = B_NH_bits
    basic_hdr["basic_reserved"] = int(etsi_dump[2:4], 16)
    LT_hex = int(etsi_dump[4:6], 16)
    multiplier_value = (LT_hex & 252) >> 2
    LT["multiplier"] = multiplier_value
    base_bits = LT_hex & 3
    LT["base"] = base_bits
    if base_bits == 0:
        LT["base"] = ("0" "=" + "(50 ms)")
    else:
        None
    if base_bits == 1:
        LT["base"] = ("1" "=" + "(1 sec)")
    else:
        None
    if base_bits == 2:
        LT["base"] = ("2" "=" + "(10 s)")
    else:
        None
    if base_bits == 3:
        LT["base"] = ("3" "=" + "(100 s)")
    else:
        None
    basic_hdr["RHL"] = int(etsi_dump[6:8], 16)
    etsi_dump = etsi_dump[8:]
    return etsi_dump


def common_hdr_dec(etsi_dump):
    global common_hdr
    ch_hex = int(etsi_dump[0:2], 16)
    C_NH_bits = (ch_hex & 240) >> 4
    common_hdr["common_next_header"] = C_NH_bits
    common_hdr["common_reserved1"] = ch_hex & 15
    HT_HST_hex = int(etsi_dump[2:4], 16)
    HT_bits = (HT_HST_hex & 240) >> 4
    common_hdr["header_type"] = HT_bits
    HST_bits = HT_HST_hex & 15
    common_hdr["header_sub_type"] = HST_bits
    TC_hex = int(etsi_dump[4:6], 16)
    scf_bits = (TC_hex & 128) >> 7
    TC["scf"] = scf_bits
    channel_offload_bits = (TC_hex & 64) >> 6
    TC["channel_offload"] = channel_offload_bits
    tc_id_bits = TC_hex & 63
    TC["tc_id"] = tc_id_bits
    flags_hex = int(etsi_dump[6:8], 16)
    flags_mob_bits = (flags_hex & 128) >> 7
    flags_mob["gnsismobile"] = flags_mob_bits
    mob_stationary["stationary"] = 0 if flags_mob_bits == 0 else None
    mob_stationary["mobile"] = 1 if flags_mob_bits == 1 else None
    flags_mob["flags_reserved"] = flags_hex & 127
    common_hdr["payload_length"] = int(etsi_dump[8:12], 16)
    common_hdr["max_hoplimit"] = int(etsi_dump[12:14], 16)
    common_hdr["common_reserved2"] = int(etsi_dump[14:16], 16)
    etsi_dump = etsi_dump[16:]
    return etsi_dump


# yet to write
"""def secure_dec(etsi_dump):"""


def lpv_dec(etsi_dump):
    lpv_dump = etsi_dump[0:48]
    so_gn_addr_hex = lpv_dump[0:16]
    gn_addr_hex = int(so_gn_addr_hex[0:4], 16)
    gn_addr_m = gn_addr_hex
    gn_addr["manual_addr_conf"] = (gn_addr_m & 32768) >> 15
    gn_addr["station_type"] = (gn_addr_m & 31744) >> 10
    gn_addr["station_country_code"] = gn_addr_m & 1023
    gn_addr_mac = so_gn_addr_hex[4:16]
    so_mac_convert = ':'.join([gn_addr_mac[i:i+2]
                               for i in range(0, len(gn_addr_mac), 2)])
    gn_addr["MID"] = so_mac_convert
    lpv_tst = lpv_dump[16:]
    lpv["so_tst"] = int(lpv_tst[:8], 16)
    lpv_lat = lpv_tst[8:]
    lpv["so_lat"] = int(lpv_lat[:8], 16)
    lpv_long = lpv_lat[8:]
    lpv["so_long"] = int(lpv_long[:8], 16)
    lpv_psh_rest = lpv_long[8:]
    lpv_pai_speed = int(lpv_psh_rest[0:4], 16)
    lpv["pai"] = (lpv_pai_speed & 32768) >> 15
    speed = lpv_pai_speed & 32767
    lpv["speed"] = speed
    lpv["heading"] = int(lpv_psh_rest[4:8], 16)
    etsi_dump = etsi_dump[48:]
    return etsi_dump


# yet to write
# def spv_dec(etsi_dump):


# yet to write
# def guc_pkt_hdr_dec(etsi_dump):


def tsb_pkt_hdr_dec(etsi_dump):
    sn_bits = int(etsi_dump[0:2], 16)
    tsb_pkt_hdr["sequence_number"] = sn_bits
    tsb_pkt_hdr["tsb_reserved"] = int(etsi_dump[2:4], 16)
    etsi_dump = etsi_dump[4:]
    etsi_dump = lpv(etsi_dump)
    tsb_pkt_hdr["so_pv"] = lpv
    return etsi_dump


def shb_pkt_hdr_dec(etsi_dump):
    etsi_dump = lpv_dec(etsi_dump)
    shb_pkt_hdr["so_pv"] = lpv
    shb_pkt_hdr["shb_reserved"] = int(etsi_dump[:8], 16)
    etsi_dump = etsi_dump[8:]
    return etsi_dump


def gbc_pkt_hdr_dec(etsi_dump):
    gbc_pkt_hdr["sequence_number"] = int(etsi_dump[0:4], 16)
    gbc_pkt_hdr["gbc_reserved1"] = int(etsi_dump[4:8], 16)
    etsi_dump = etsi_dump[8:]
    etsi_dump = lpv_dec(etsi_dump)
    gbc_pkt_hdr["so_pv"] = lpv
    gbc_pkt_hdr["geo_area_pos_lat"] = int(etsi_dump[0:8], 16)
    gbc_pkt_hdr["geo_area_pos_long"] = int(etsi_dump[8:16], 16)
    dista = int(etsi_dump[16:20], 16)
    gbc_pkt_hdr["dist_a"] = dista
    distb = int(etsi_dump[20:24], 16)
    gbc_pkt_hdr["dist_b"] = distb
    angle = int(etsi_dump[24:28], 16)
    gbc_pkt_hdr["angle"] = angle
    gbc_pkt_hdr["gbc_reserved2"] = int(etsi_dump[28:32], 16)
    etsi_dump = etsi_dump[32:]
    return etsi_dump


def beacon_pkt_hdr_dec(etsi_dump):
    etsi_dump = lpv_dec(etsi_dump)
    beacon_pkt_hdr["so_pv"] = lpv
    return etsi_dump


def btp_hdr_dec(etsi_dump):
    """ Author: Nilesh Guhe
    """
    global btp_hdr
    try:
        btp_hdr["dest_port"] = int(etsi_dump[0:4], 16)
        btp_hdr["dest_port_info"] = int(etsi_dump[4:8], 16)
        etsi_dump = etsi_dump[8:]
    except ValueError:
        print("BTP has no beacon packet")
    return etsi_dump

# yet to write
# def ls_req_dec(etsi_dump):


# yet to write
# def ls_reply_dec(etsi_dump):

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Provide enough arguments")
        print("Usage:Python etsihead.py <hexdump>")
        exit(0)
    gn_hdr_init()
    hexdump = sys.argv[1]
    hexdump = re.sub(r"\s+", "", hexdump)
    llc_head = "8947"
    llc_head_pos = re.search(llc_head, hexdump)
    etsi_dump = None
    if llc_head_pos:
        llc_head_pos_end = llc_head_pos.end()
        etsi_dump = hexdump[llc_head_pos_end:]
    else:
        etsi_dump = hexdump
    etsi_dump = gn_hdr_dec(etsi_dump)
    etsi_dump = redirecting_api(etsi_dump)
    etsi_dump = btp_hdr_dec(etsi_dump)
    print(etsi_dump)
    print(json.dumps(gn_hdr, indent=2))
