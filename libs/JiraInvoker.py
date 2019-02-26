#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os

safe_fw_path = sys.argv[1]
sys_path_refer = safe_fw_path.split("safe")[0]
sys_path_refer = os.path.abspath(safe_fw_path)
#sys_path_refer = "/home/raviteja/Desktop/Automation/safe"
print(sys_path_refer)
sys.path.append("%s/target/classes/" % sys_path_refer)
sys.path.append("%s/target/test-classes/" % sys_path_refer)
sys.path.append("%s/common" % sys_path_refer)
sys.path.append("%s/common/lib/javax.activation-api-1.2.0.jar" %
                sys_path_refer)
sys.path.append("%s/common/lib/jaxb-api-2.3.0.jar" % sys_path_refer)
sys.path.append("%s/common/lib/jaxb-core-2.3.0.1.jar" % sys_path_refer)
sys.path.append("%s/common/lib/jaxb-impl-2.3.0.1.jar" % sys_path_refer)
sys.path.append("%s/common/lib/h2-1.4.197.jar" % sys_path_refer)
sys.path.append("%s/common/lib/hamcrest-core-1.1.jar" % sys_path_refer)
sys.path.append(
    "%s/common/lib/jersey-client-1.19.4.jar" % sys_path_refer)
sys.path.append("%s/common/lib/jersey-core-1.19.4.jar" % sys_path_refer)
sys.path.append("%s/common/lib/json-20180130.jar" % sys_path_refer)
sys.path.append("%s/common/lib/json-simple-1.1.1.jar" % sys_path_refer)
sys.path.append("%s/common/lib/jsr311-api-1.1.1.jar" % sys_path_refer)
sys.path.append("%s/common/lib/junit-4.10.jar" % sys_path_refer)
sys.path.append("%s/common/lib/jython-1.0.jar" % sys_path_refer)
sys.path.append("%s/common/lib/logback-core-1.2.3.jar" % sys_path_refer)
sys.path.append("%s/common/lib/slf4j-api-1.7.25.jar" % sys_path_refer)
sys.path.append("%s/common/lib/slf4j-simple-1.7.25.jar" % sys_path_refer)
sys.path.append("%s/common/lib/javax.mail-1.5.6.jar" % sys_path_refer)
from com.innominds.team.pjython import JiraCreator

#JiraCreator.invokeJiraCreator("11420", "10103", "#Automated:TL-877", "TestLink: Automation failure: Please check logs", "NA");
args = sys.argv[2]
# print(sys.path)
args_list = args.split(",")
#JiraCreator.invokeJiraCreator("%s"%args_list[0], "%s"%args_list[1], "%s"%args_list[2], "%s"%args_list[3], "%s"%args_list[4])
JiraCreator.invokeJiraCreator(args_list[0], args_list[1], args_list[2], args_list[3], args_list[4])
