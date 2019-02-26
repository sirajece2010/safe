*** settings ***
Library        /home/innominds/Innominds/Automation/safe/libs/main.py
Library        String
Library        OperatingSystem

*** Variables ***
*** TestCases ***
Scenario:Average Start up Time for an OBU including Linux boot time(Hard reboot with ignition)
        ${status}=        main.start_of_testcase        obu_kpi_flow.txt

        ${status}=        main.logger_config        obu_kpi_flow.txt
        ${status}=        main.jira_attributes_func        Scenario:Average Start up Time for an OBU including Linux boot time(Hard reboot with ignition)

        ${OBU1}=        main.obu_connect_to_device        OBU1
        ${status}=        main.obu_cleanup_func        ${OBU1}        OBU1
        ${status}=        main.command        ${OBU1}        OBU1        obu cat /etc/banner
        ${status}=        main.command        ${OBU1}        OBU1        child close        OBU1
        ${status}=        main.end_of_testcase