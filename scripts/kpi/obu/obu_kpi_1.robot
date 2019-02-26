*** settings ***
Library        /home/innominds/Innominds/Automation/safe/libs/main.py
Library        String
Library        OperatingSystem

*** Variables ***
*** TestCases ***
Scenario:Average Start up Time for an OBU including Linux boot time(Hard reboot with ignition)
        ${status}=        main.start_of_testcase        obu_kpi_1.txt

        ${status}=        main.logger_config        obu_kpi_1.txt
        ${status}=        main.jira_attributes_func        Scenario:Average Start up Time for an OBU including Linux boot time(Hard reboot with ignition)

        ${OBU4}=        main.obu_connect_to_device        OBU4
        ${status}=        main.obu_cleanup_func        ${OBU4}        OBU4
        ${status}=        main.command        ${OBU4}        OBU4        obu cat /etc/banner
