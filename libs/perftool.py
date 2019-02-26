# -*- coding: utf-8 -*-
'''
    File name: libRSE.py
    Author: Ravi Teja Nagamothu
    Date created: 15/11/2018
    Python Version: 3.6
'''
import libRSE
import pandas as pd
import tqdm
from colorama import Fore
import traceback
config = libRSE.config
json = libRSE.json
sleep = libRSE.sleep
os = libRSE.os
re = libRSE.re
pexpect = libRSE.pexpect
datetime = libRSE.datetime

AUTOTALKS = False
RV_CONF = None
HV_CONF = None
TOP_CMD_ITER = 6
TOP_CMD_SLP = 1

RV_PROC_LIST = []  # used to store all rvs connections. refer rvs_cmd_exec_func
RVS_PER_BOARD = 10


def csv_creator(fn, df):
    global TOP_CMD_ITER
    cpu_cnt = TOP_CMD_ITER
    file_name = fn
    with open(file_name, "r") as data:
        db = data.read()
    al_data = []
    bsmd_data = []
    savarid_data = []
    try:
        hr_min_sec = [(int(i), int(j), int(k)) for i, j, k in
                      re.findall(r"Last tx/rx timestamp:[\s\d/]+-(\d+):(\d+):(\d+)", db)]
    except Exception:
        print("Exception while calculating time diff")
    time_in_sec = [3600*hr + mn*60 + sec for hr, mn,
                   sec in hr_min_sec]  # converting time to sec
    time_diff = [time_in_sec[i]-time_in_sec[i-1]
                 for i in range(1, len(time_in_sec))]
    num_rx_list = [int(i) for i in re.findall(r"Num Rx:[\s]+(\d+)", db)]
    # Finding the diff btw two asd_stats
    num_rx_diff = [num_rx_list[i] - num_rx_list[i-1]
                   for i in range(1, len(num_rx_list))]
    num_rx_diff_avg = [round(i/td)
                       for i, td in zip(num_rx_diff, time_diff) if td != 0]
    bsm_data_index = [i.span()[0] for i in re.finditer(r"BSM Data:", db)]
    for ind in range(1, len(bsm_data_index)):
        i1, i2 = bsm_data_index[ind-1], bsm_data_index[ind]
        # Finding aerolink, bsmd, savarid cpu values
        aerolink = [int(i) for i in re.findall(
            r"(\d+)%[\s\./]+AeroLink", db[i1:i2])]
        bsmd = [int(i) for i in re.findall(r"(\d+)%[\s\./]+BSMd", db[i1:i2])]
        savarid = [int(i) for i in re.findall(
            r"(\d+)%[\s\./]+savari16093d", db[i1:i2])]
        #for i,j,k in zip(aerolink, bsmd, savarid):
        #    print(i,j,k)
        # Checking the len of the values should be equal to num of
        # snapshots of top on each iteration
        if (len(aerolink), len(bsmd), len(savarid)) == (cpu_cnt,)*3:
            # Ignoring the first two values and taking avg of remaining cpu values
            # print("CPUCNT:", cpu_cnt)
            al_data.append(sum(aerolink[2:])/(cpu_cnt-2))
            bsmd_data.append(sum(bsmd[2:])/(cpu_cnt-2))
            savarid_data.append(sum(savarid[2:])/(cpu_cnt-2))
            # print(al_data, bsmd_data, savarid_data)
        else:
            print("error occurred")
            print("May be one/all of the process got killed")
            print("refer raw data.")
            return -1
    al_data = [round(i, 3) for i in al_data]
    bsmd_data = [round(i, 3) for i in bsmd_data]
    savarid_data = [round(i, 3) for i in savarid_data]
    rvs_cnt = re.search(r"(\d+)", file_name).group(1)
    al_data = pd.Series(al_data)
    bsmd_data = pd.Series(bsmd_data)
    savarid_data = pd.Series(savarid_data)
    df["num_rx_diff_{}".format(rvs_cnt)] = num_rx_diff
    df["time_stamp_diff_{}".format(rvs_cnt)] = time_diff
    df["num_rx_diff_avg_{}".format(rvs_cnt)] = num_rx_diff_avg
    df["aerolink_{}".format(rvs_cnt)] = al_data
    df["bsmd_{}".format(rvs_cnt)] = bsmd_data
    df["savarid_{}".format(rvs_cnt)] = savarid_data
    return df


def raw_data_parser(raw_data_dir):
    pwd = os.getcwd()
    os.chdir(raw_data_dir)
    # Getting the list of all raw data files
    fn_list = os.listdir(raw_data_dir)
    fn_list.sort()
    df = pd.DataFrame()  # Creating dataframe to add all the parsed values
    for fn in fn_list:
        if("data" in fn):
            print("Parsing the file:{}".format(fn))
            df = csv_creator(fn, df) #raw data file_names, data frame
            if type(df) != pd.core.frame.DataFrame:
                return -1
    bn = os.path.basename(raw_data_dir)
    csv_file = "{}.csv".format(bn)
    df.to_csv(csv_file, index=False)
    print("Created csv file:{}".format(csv_file))
    os.chdir(pwd)
    return df


def connect_to_device_atk(dev_key):
    global AUTOTALKS
    pmt = "autotalks:"
    dev_lgn_dtils = config.OBU_Dict[dev_key]
    ip_addr = dev_lgn_dtils["OBU_HOSTIP"]
    ssh_cmd = "ssh root@{}".format(ip_addr)
    child = pexpect.spawn(ssh_cmd)
    try:
        child.expect(pmt)
    except pexpect.TIMEOUT:
        child.expect("connecting")
        child.sendline("yes")
        child.expect(pmt)
    AUTOTALKS = True
    print("Connected to autotalks:{}".format(ip_addr))
    return child


def connect_to_device_sbr(dev_key):
    child = None
    return child


def timestamp_func():
    timestamp = datetime.datetime.now()
#    date = str(timestamp.date())
#    time = str(timestamp.time())
    timestamp = "{}_{}_{}_{}".format(timestamp.day,
                                     timestamp.hour,
                                     timestamp.minute,
                                     timestamp.second)
    return timestamp


def obu_scp_atk(child, cmd, *args):
    dev_pmt = "autotalks:"
    try:
        source = args[0]
        dest = args[1]
        command = None
        if re.search(r"resource", dest):
            dest = dest.split("resource")[1]
            command = "scp {0} {1}@{2}:{3}/resource{4}".format(source,
                                                               config.SYS_UNAME,
                                                               config.SYS_HOST,
                                                               config.SAFE_FW_PATH,
                                                               dest)
        else:
            command = "scp {} {}@{}:{}".format(source, config.SYS_UNAME,
                                               config.SYS_HOST, dest)
        #print("OBU command:{}".format(command))
        child.sendline("")
        child.expect(dev_pmt)
        child.sendline("{}".format(command))
        try:
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting", timeout=5)
            child.sendline("yes\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        sleep(2)
        child.expect(dev_pmt, timeout=1000)
        data = child.before
        data = str(data, "utf-8")
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened while executing \"{}\"".format(command))
        return None


def obu_scp_sys_atk(child, cmd, *args):
    dev_pmt = "autotalks:"
    try:
        source = args[0]
        dest = args[1]
        if re.search(r"resource", source):
            source = source.split("resource")[1]  # source has '/'
            command = "scp {0}@{1}:{2}/resource{3} {4}".format(config.SYS_UNAME,
                                                               config.SYS_HOST,
                                                               config.SAFE_FW_PATH,
                                                               source,
                                                               dest)
        else:
            command = "scp {}@{}:{} {}".format(config.SYS_UNAME, config.SYS_HOST,
                                               source, dest)
        print(command)
        child.sendline("{}\r".format(command))
        try:
            child.expect("password", timeout=10)
            child.sendline(config.SYS_PASSWORD)
        except pexpect.TIMEOUT:
            child.expect("connecting", timeout=5)
            child.sendline("yes\r")
            child.expect("password:")
            child.sendline(config.SYS_PASSWORD)
        sleep(2)
        child.expect(dev_pmt, timeout=1000)
        data = child.before
        data = str(data, "utf-8")
        return data
    except TypeError:
        print("Not connected to the device or child is unknown")
        return None
    except pexpect.EOF:
        print("Number of logins are exceeded or connection lost")
        return None


def obu_file_config(child, cmd, *args):
    try:
        child.sendline("")
        child.expect(config.OBUPMT)
        try:
            path = args[0]
            field_to_change = args[1]
            value = str(args[2])
            if len(args) > 3 and args[3] == 'space':
                delimiter = ' '
            else:
                delimiter = '='
        except IndexError:
            print("Please provide valid arguments to config the file")
            return 0
        if re.search(r"/", value):
            value = re.sub("/", r"\/", value)
            print(value)
        if value == "NULL":
            command = r"sed -i 's/^{0} *{1} *\"*[_\.\-\s:/0-9a-zA-Z]*\"*/{0}          = /g' \
                    {3}".format(field_to_change, delimiter, value, path)
        elif "\"" not in value:
            command = r"sed -i 's/^{0} *{1} *[_\.\-\s:/0-9a-zA-Z]*/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        else:
            command = r"sed -i 's/^{0} *{1} *\"[_\.\-\s:/0-9a-zA-Z]*\"/{0}          {1} {2}/g' \
            {3}".format(field_to_change, delimiter, value, path)
        child.sendline(command)
        child.expect(config.OBUPMT)
        awk_cmd = "awk '/{}/ {{{}}}' {}".format(field_to_change, "print", path)
        child.sendline(awk_cmd)
        child.expect(config.OBUPMT)
        awk_data = str(child.before, "utf-8")
        return awk_data
    except IndexError:
        print("Please provide the valid number of arguments")
        return None
    except pexpect.TIMEOUT:
        print("Timeout happened in obu_file_config function")
        return None


def perf_shell_script(var_dict, dev_pmt):
    safe_fw_path = config.SAFE_FW_PATH
    num_of_iter = 60 * int(var_dict["time_intvl"])
    num_of_iter = int(num_of_iter/(TOP_CMD_SLP*TOP_CMD_ITER))
    data_path = "{}/resource/devperf/{}".format(safe_fw_path, "data.sh")
    with open(data_path, "w") as data_script:
        data_script.write("#!/bin/sh\n\n")
        data_script.write("num_of_iter={}\n".format(num_of_iter))
        data_script.write("while [ $num_of_iter -gt 0 ]\n")
        data_script.write("do\n")
        # data_script.write("\tdate +%s >> data.txt\n")
        data_script.write("\tasd_stats -b >> data.txt\n")
        data_script.write("\ttop -d {} -n {} >> data.txt\n".format(TOP_CMD_SLP,
                                                                   TOP_CMD_ITER))
        # data_script.write("\tdate +%s >> data.txt\n")
        data_script.write("\tsleep 1\n")
        data_script.write("\tnum_of_iter=`expr $num_of_iter - 1`\n")
        data_script.write("done\n")
    return data_path


def collect_data_from_hv_func(var_dict, num_of_rvs):
    global AUTOTALKS
    dev_pmt = None
    if AUTOTALKS:
        dev_pmt = "autotalks:"
    else:
        dev_pmt = config.OBUPMT
    safe_fw_path = config.SAFE_FW_PATH
    data_path = perf_shell_script(var_dict, dev_pmt)
    child_hv = var_dict["child_hv"]
    child_hv.sendline("cd && mv data.txt /nojournal/")
    child_hv.expect(dev_pmt)
    num_of_iter = 60 * int(var_dict["time_intvl"])
    num_of_iter = int(num_of_iter/(TOP_CMD_SLP*TOP_CMD_ITER))
    if AUTOTALKS:
        obu_scp_sys_atk(child_hv, "obu scp sys", data_path, "/home/root/")
        print("File copied.")
    else:
        libRSE.obu_scp_sys(child_hv, "obu scp sys", data_path, "/home/")
        print("File copied.")
    child_hv.sendline("chmod 777 data.sh")
    child_hv.expect(dev_pmt)
    child_hv.sendline("./data.sh")
    print(Fore.GREEN)
    for i in tqdm.tqdm(range(num_of_iter)):
        sleep(TOP_CMD_ITER)
    print(Fore.BLACK)
    child_hv.expect(dev_pmt, timeout=3600)
    print("Data collected")
    raw_data = "{}/data_{}.txt".format(var_dict["hv_rv_data"], num_of_rvs)
    if AUTOTALKS:
        obu_scp_atk(child_hv, "obu scp", "data.txt", raw_data)
        print("File copied.")
    else:
        libRSE.obu_scp(child_hv, "obu scp", "data.txt", raw_data)
        print("File copied.")
    child_hv.sendline("rm data.txt")
    child_hv.expect(dev_pmt)
    return raw_data


def config_rv_func(child_rv, rv_config_path, rv_conf):
    # code to read data from csv file
    safe_fw_path = os.path.abspath(config.SAFE_FW_PATH)
    rv_config_file = pd.read_csv(rv_config_path)
    col_names = rv_config_file.columns  # path, filed_to_change, value
    conf_obj = zip(rv_config_file[col_names[0]],
                   rv_config_file[col_names[1]],
                   rv_config_file[col_names[2]])
    for path, field, value in conf_obj:
        #print(f"P:{path} F:{field} V:{value}")
        if re.search("PreRecFileName", field):
            value = rv_conf  # need to change value to RV*.csv
            pre_record_file = "{}/resource/devperf/{}".format(safe_fw_path,
                                                              rv_conf)
            libRSE.obu_scp_sys(child_rv,
                               "obu scp", pre_record_file,
                               "/etc/config/{}".format(rv_conf))
        print("Configuring {} to {}".format(field, value))
        awk_data = obu_file_config(child_rv, "file config",
                                   path.strip(),
                                   field.strip(), value)
        awk_data = awk_data.split("\n")[1]
        print(Fore.GREEN + awk_data + Fore.BLACK)
    return


def rvs_cmd_exec_func(var_dict, ip, num_of_rvs):
    global RV_PROC_LIST
    child_rv = libRSE.obu_connect_to_device(var_dict["device"], ip_addr=ip)
    RV_PROC_LIST.append((child_rv, ip))
    config_rv_func(child_rv, var_dict["rv_config_path"], var_dict["rv_conf"])
    child_rv.sendline("halt;run")
    child_rv.expect(config.OBUPMT)
    #child_rv.sendline("/etc/init.d/bsmd stop")
    # child_rv.expect(config.OBUPMT)
    #freq = 100/num_of_rvs
    # cmd = "BSMd -i /etc/config/ -N {} -T {} -P 2 -D 0 -R 8".format(
    #    num_of_rvs, int(freq))
    # print(cmd)
    #child_rv.sendline("{} &".format(cmd))
    # child_rv.sendline("halt;run")
    # child_rv.expect(config.OBUPMT)
    child_rv.sendline("ps > ps.txt")
    child_rv.expect(config.OBUPMT)
    return 1


def halt_used_rvs():
    global RV_PROC_LIST
    print("Halting all the rvs")
    for child, ip in RV_PROC_LIST:
        try:
            if child.isalive():
                child.sendline("halt")
                child.expect(config.OBUPMT)
                print("Device with ip:{} in halt state".format(ip))
                child.close(force=True)
        except Exception:
            print("Connection lost")
            print("Unable to process halt command for {}".format(ip))
    return


def simulate_rvs_func(var_dict, get_ip, get_rv_conf):
    global RVS_PER_BOARD
    num_of_rvs = var_dict["rvs_step"]  # Num of rvs to start the simulation
    max_rvs = var_dict["max_rvs"]
    rvs_used = 0
    rvs_per_board = RVS_PER_BOARD
    while num_of_rvs <= max_rvs:
        if num_of_rvs >= rvs_used * rvs_per_board:
            try:
                ip = get_ip.__next__()
            except StopIteration:
                print("No valid ips or all rv ips are used")
                print("exiting from the script")
                break
            # when ip changes configure file should change
            var_dict["rv_conf"] = get_rv_conf.__next__()
        rvs_cmd_exec_func(var_dict, ip, num_of_rvs)
        status = collect_data_from_hv_func(var_dict, num_of_rvs)
        if status:
            num_of_rvs += var_dict["rvs_step"]
            rvs_used += 1
    print("Simulation completed.")
    return


def var_init(child_hv_key, rv_key, rv_config_file,
             max_rvs, time_intvl, sim_type, rvs_step):
    libRSE.start_of_testcase("perftool")
    libRSE.health_check_var_init()
    if re.search(r"ATK", child_hv_key):
        child_hv = connect_to_device_atk(child_hv_key)
        if not child_hv:
            print("Not connected to HV")
            return -1
    elif re.search(r"SBR", child_hv_key):
        child_hv = connect_to_device_sbr(child_hv_key)
    else:
        child_hv = libRSE.obu_connect_to_device(child_hv_key)
    safe_fw_path = config.SAFE_FW_PATH
    timestamp = timestamp_func()
    hv_rv_data = "{}/resource/devperf/{}_{}".format(safe_fw_path, sim_type,
                                                    timestamp)
    rv_config_path = "{}/resource/devperf/{}".format(
        os.path.abspath(safe_fw_path), rv_config_file)
    var_dict = {
        "child_hv_key": child_hv_key,
        "child_hv": child_hv,
        "device": rv_key,
        "max_rvs": int(max_rvs),
        "rvs_step": int(rvs_step),
        "rv_config_path": rv_config_path,
        "time_intvl": int(time_intvl),
        "hv_rv_data": hv_rv_data
    }
    print("Creating Directory:", Fore.GREEN+hv_rv_data+Fore.BLACK)
    os.system("mkdir {}".format(hv_rv_data))
    return var_dict


def date_sync(child_hv_key, rv_key, date_cmd = "date -s '2018-11-19 14:04:00'"):
    dev_conn = dict()
    libRSE.start_of_testcase("perftool")
    libRSE.health_check_var_init()
    rv_ip = config.OBU_Dict[rv_key]["OBU_HOSTIP"]
    for ip in rv_ip:
        child = libRSE.obu_connect_to_device(rv_key, ip_addr=ip)
        dev_conn[ip] = child
    child = connect_to_device_atk(child_hv_key)
    hv_ip = config.OBU_Dict[child_hv_key]["OBU_HOSTIP"]
    dev_conn[hv_ip] = child
    for key in dev_conn.keys():
        child = dev_conn[key]
        print("Setting date to:{}".format(key))
        child.sendline(date_cmd)
        child.expect("({})|({})".format(config.OBUPMT, "autotalks"))
        print(child.before)
        child.close(force=True)
    return 1


def main(child_hv_key, rv_key, rv_config_file,
         max_rvs, time_intvl, sim_type="sec_on_app_on",
         rvs_step=None):
    # child_hv-- is connection to HV
    # rv_key-- dictionary key to fetch rv details.Defined in config.py
    # max_rvs-- num_of_rvs to simulate
    # rvs_step--num of rvs should be incremented by each iteration should be
               # less than num of rvs simulated in each rv
    # rv_config_path-- config file to configure rvs
    # time_intvl-- time required (min) to collect data by hv
    #date_sync(child_hv_key, rv_key)
    var_dict = var_init(child_hv_key, rv_key, rv_config_file,
                        max_rvs, time_intvl, sim_type, rvs_step)
    if var_dict == -1:
        return -1
    dev_lgn_dtils = config.OBU_Dict[rv_key]
    get_ip = (i for i in dev_lgn_dtils["OBU_HOSTIP"])
    get_rv_conf = (i for i in dev_lgn_dtils["conf_files"])
    simulate_rvs_func(var_dict, get_ip, get_rv_conf)
    try:
        raw_data_parser(var_dict["hv_rv_data"])
    except Exception:
        print("Exception while parsing the data")
        print("Do it manually")
        print(traceback.format_exc())
    return 1

if __name__ == "__main__":
    for i in range(1):
        try:
            main("OBUATKHV1", "OBURV1", "rv_configcsv.csv",
                 160,2, rvs_step = 10, sim_type="sec_on_app_on")
            halt_used_rvs()
        except Exception:
            halt_used_rvs()
            print(traceback.format_exc())
