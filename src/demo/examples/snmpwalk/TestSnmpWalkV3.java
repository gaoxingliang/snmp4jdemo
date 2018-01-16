package demo.examples.snmpwalk;

import demo.DebuggerLogFactory;
import demo.examples.SnmpV3Util;
import org.snmp4j.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.util.List;

/**
 * test a snmp walk request by using snmp v3
 * Created by edward.gao on 07/09/2017.
 */
public class TestSnmpWalkV3 {

    /**
     * Send a snmp get v3 request to request the remote device host name and uptime
     * @param args  [remote device Ip, remote device port, security, authProtocol, authToken, privProtocol, privToken, oid, getbulk(true|false)]
     *
     *              Example: 192.168.170.149 161 testUser md5 testAuth des privPass 1.3.6.1.2.1.2.2.1.2 true
     */
    public static void main(String[] args) throws Exception {

        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());

        if (args.length < 8) {
            _printUsage();
            return;
        }

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String security = args[2];
        String authProtocol = args[3];
        String authToken = args[4];
        String privProtocol = args[5];
        String privToken = args[6];
        String oid = args[7];
        boolean useBulk = args.length > 8 ? Boolean.valueOf(args[8]) : true;
        if (security.isEmpty()) {
            System.out.println("Security is empty, this is required");
            return;
        }

        System.out.println(String.format("Send message version 3 to %s:%d with security=%s,authProtol=%s,authToken=%s,privProtocol=%s,privToken=%s,oid=%s",
                ip, port, security, authProtocol, authToken, privProtocol, privToken, oid));
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        Snmp snmp = new Snmp(messageDispatcher, new DefaultUdpTransportMapping());
        OID authProtocolOID = SnmpV3Util.getAuthProtocol(authProtocol);
        OID privacyProtocolOID = SnmpV3Util.getPrivacyProtocol(privProtocol);

        int securityLevel = 0;
        if (authProtocolOID == null) {
            System.out.println("No authentication protocol set, related privacy will be disabled");
            securityLevel = SecurityLevel.NOAUTH_NOPRIV;
        }
        else {
            if (privacyProtocolOID == null) {
                securityLevel = SecurityLevel.AUTH_NOPRIV;
                System.out.println("No privacy protocol set");
            }
            else {
                securityLevel = SecurityLevel.AUTH_PRIV;
                System.out.println("Privacy protocol set");
            }
        }

        System.out.println("Use bulk - " + useBulk);
        if (!useBulk) {
            SNMP4JSettings.setNoGetBulk(true);
        }

        OctetString localEngineID = new OctetString(
                MPv3.createLocalEngineID());
        SecurityProtocols.getInstance().addDefaultProtocols();
        // you can add some other undefault protocols
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
        //Enable the usm to discover the engineId automatically
        usm.setEngineDiscoveryEnabled(true);
        MPv3 mPv3 = new MPv3(usm);
        UsmUser user = new UsmUser(new OctetString(security), authProtocolOID, new OctetString(authToken), privacyProtocolOID, new OctetString(privToken));
        usm.addUser(user);

        /**
         * important add some other protocols
         * here add an example for 3des
         *
         * @see SecurityProtocols#addDefaultProtocols()
         */
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
        SecurityModels.getInstance().addSecurityModel(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(mPv3);

        snmp.listen();

        UserTarget target = new UserTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(5000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(securityLevel);
        target.setSecurityName(new OctetString(security));


        OID rootOID = new OID(oid);

        // difference part here
        // for a v3 version, set it's contextName and contextID to avoid NPE
        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory(PDU.GET, new OctetString(""),  new OctetString("")));
        List<TreeEvent> resultEvents = treeUtils.getSubtree(target, rootOID);
        if (resultEvents == null || resultEvents.isEmpty()) {
            System.out.println("No result found, please check the community");
        }
        else {
            for (TreeEvent treeEvent : resultEvents) {
                VariableBinding[] vbs = treeEvent.getVariableBindings();
                for (VariableBinding vb : vbs) {
                    System.out.println(String.format("Receive oid=%s value=%s", vb.getOid(), vb.getVariable()));
                }
            }
        }

    }

    private static void _printUsage() {
        System.out.println("Arguments error. " + TestSnmpWalkV3.class.getName() + " [remote device Ip, remote device port, security, authProtocol, authToken, privProtocol, privToken, oid, getbulk]");
        System.out.println("security is the user name");
        System.out.println("authProtocol is the authentication protocol, now support MD5 and SHA");
        System.out.println("authToken is the authentication passphrase");
        System.out.println("privProtocol is the privacy protocol, now support DES/AES/AES128/3DES/AES256/AES384 (some may be restricted by jdk)");
        System.out.println("privToken is the privacy passpharse");
        System.out.println("Example: 192.168.170.149 161 testUser md5 testAuth des privPass 1.3.6.1.2.1.2.2.1.2 true");
    }
}
