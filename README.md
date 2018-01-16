# snmp4jdemo
Create a demo examples for snmp4j usage

# How to enable or create snmp v3 users
on a linux system:
1. service snmpd stop
2. net-snmp-create-v3-user [-ro] [-A authpass] [-X privpass]
                             [-a MD5|SHA] [-x DES|AES] [username]
                             
                             

# build it in a fatjar
``
gradle fatjar
``

# Snmp4j best practice
In order to avoid you don't know what You inited.
Please call:<br>
```
MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
Snmp snmp = new Snmp(messageDispatcher, new DefaultUdpTransportMapping());
```
And then register snmp v3 related credentials:
```
OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
SecurityProtocols.getInstance().addDefaultProtocols();
USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
//Enable the usm to discover the engineId automatically
usm.setEngineDiscoveryEnabled(true);
MPv3 mPv3 = new MPv3(usm);
UsmUser user = new UsmUser(new OctetString(security), authProtocolOID, new OctetString(authToken), privacyProtocolOID, new OctetString(privToken));
usm.addUser(user);
// you can add some other undefault protocols
SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
SecurityModels.getInstance().addSecurityModel(usm);
snmp.getMessageDispatcher().addMessageProcessingModel(mPv3);
```

Then:
```
snmp.listen()
```