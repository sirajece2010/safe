import libRSE
import main
libRSE.health_check_var_init()
libRSE.start_of_testcase("abc")

child=libRSE.obu_connect_to_device("OBUCOC4")
x=libRSE.obu_tcpdump(child,"obu tcpdump","ath0","Pin","00:01:02:03:04:06")
child.close()
