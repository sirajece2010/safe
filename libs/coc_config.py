sock_dtils = {}

# IUT1 should be always the board under test
#(To avoid coc application to be killed if test case fails)

sock_dtils["RSUIUT2"] = {
    "ip addr sys": "192.168.20.162",
    "ip addr IUT": "192.168.22.93",
    "udp port": 13001
}
    
sock_dtils["RSUIUT1"] = {
    "ip addr sys": "192.168.20.162",
    "ip addr IUT": "10.0.0.131",
    "udp port": 13001
}

sock_dtils["OBUIUT1"] = {
    "ip addr sys": "192.168.20.162",
    "ip addr IUT": "10.0.0.61",
    "udp port": 13001
}
sock_dtils["OBUIUT2"] = {
    "ip addr sys": "192.168.20.162",
    "ip addr IUT": "10.0.0.172",
    "udp port": 13001
}
ota_dev_dtils = {
    "OBU_UNAME": "root",
    "HOSTIP": "192.168.20.229",
    "OBU_PASSWORD": "5@G3p9axINJA"
}


msg_id_dot3 = {

}
