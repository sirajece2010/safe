import libRSE
import config
import main
import coc_script

libRSE.start_of_testcase("abc")

libRSE.health_check_var_init()

x=coc_script.pcap_reader_verify_psid(None,None,"127",option="data",service_type="add_user")
print(x)

