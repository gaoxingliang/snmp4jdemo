# snmp4jdemo
Create a demo examples for snmp4j usage

# How to enable or create snmp v3 users
on a linux system:
1. service snmpd stop
2. net-snmp-create-v3-user [-ro] [-A authpass] [-X privpass]
                             [-a MD5|SHA] [-x DES|AES] [username]
                             
                             

# 