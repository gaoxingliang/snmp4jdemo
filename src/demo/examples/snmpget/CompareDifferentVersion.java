package demo.examples.snmpget;

import demo.Constants;
import demo.examples.SnmpV3Util;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Compare the differences between snmp v1/v2c/v3
 * Created by edward.gao on 11/09/2017.
 */
public class CompareDifferentVersion {

    private static Snmp _snmp;
    private static String _ip;
    private static int _port;
    private static int _securityLevel;
    private static String _security;
    private static String _community;

    private static final OID _NOT_EXISTED_OID = new OID("1.3.6.1.2222.1.1.5.0");

    public static void main(String[] args) throws IOException {
        //System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());

        if (args.length < 7) {
            _printUsage();
            return;
        }

        _ip = args[0];
        _port = Integer.valueOf(args[1]);
        _community = args[2];
        _security = args[3];
        String authProtocol = args[4];
        String authToken = args[5];
        String privProtocol = args[6];
        String privToken = args[7];
        if (_security.isEmpty()) {
            System.out.println("Security is empty, this is required");
            return;
        }

        System.out.println(String.format("Send message version 3 to %s:%d with security=%s,authProtol=%s,authToken=%s,privProtocol=%s,privToken=%s",
                _ip, _port, _security, authProtocol, authToken, privProtocol, privToken));

        _snmp = new Snmp(new DefaultUdpTransportMapping());
        OID authProtocolOID = SnmpV3Util.getAuthProtocol(authProtocol);
        OID privacyProtocolOID = SnmpV3Util.getPrivacyProtocol(privProtocol);

        _securityLevel = 0;
        if (authProtocolOID == null) {
            System.out.println("No authentication protocol set, related privacy will be disabled");
            _securityLevel = SecurityLevel.NOAUTH_NOPRIV;
        }
        else {
            if (privacyProtocolOID == null) {
                _securityLevel = SecurityLevel.AUTH_NOPRIV;
                System.out.println("No privacy protocol set");
            }
            else {
                _securityLevel = SecurityLevel.AUTH_PRIV;
                System.out.println("Privacy protocol set");
            }
        }


        OctetString localEngineID = new OctetString(
                MPv3.createLocalEngineID());

        USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
        //Enable the usm to discover the engineId automatically
        usm.setEngineDiscoveryEnabled(true);
        MPv3 mPv3 = new MPv3(usm);
        UsmUser user = new UsmUser(new OctetString(_security), authProtocolOID, new OctetString(authToken), privacyProtocolOID, new OctetString(privToken));
        usm.addUser(user);
        SecurityModels.getInstance().addSecurityModel(usm);
        _snmp.getMessageDispatcher().addMessageProcessingModel(mPv3);
        _snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        _snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());

        _snmp.listen();


        System.out.println("==================Compare snmp get============");
        System.out.println("Will request three oids");
        _compareSnmpGet();
    }

    /**
     * for a snmp get request with more than one oid in one request
     * if some oid is not found,
     *      The snmp v1 will break and no other oid's value found. and contains an error index which start with 1 instead of 0
     *      The snmp v2/v3 will continue to work and no error index set.
     */
    public static void _compareSnmpGet() throws IOException {

        List<VariableBinding> _requestVbs = new ArrayList<>();
        _requestVbs.add(new VariableBinding(Constants.OID_HOSTNAME));
        _requestVbs.add(new VariableBinding(_NOT_EXISTED_OID));
        _requestVbs.add(new VariableBinding(Constants.OID_UPTIME));

        UserTarget target = new UserTarget();
        Address address = new UdpAddress(String.format("%s/%d", _ip, _port));
        target.setAddress(address);
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(5000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(_securityLevel);
        target.setSecurityName(new OctetString(_security));
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.addAll(_requestVbs);

        System.out.println("SNMP V3=================================");
        ResponseEvent responseEvent = _snmp.get(pdu, target);
        _printResponse(responseEvent);

        System.out.println("SNMP V2=================================");
        CommunityTarget v2target = new CommunityTarget();
        v2target.setCommunity(new OctetString(_community)); // community is important
        v2target.setRetries(1); // if possible, retry this request
        v2target.setTimeout(5000); // the timeout in mills for one pdu
        v2target.setVersion(SnmpConstants.version2c);
        v2target.setAddress(address);
        PDU v2pdu = new PDU();
        v2pdu.setType(PDU.GET);
        v2pdu.addAll(_requestVbs);

        responseEvent = _snmp.get(v2pdu, v2target);
        _printResponse(responseEvent);


        System.out.println("SNMP V1=================================");
        CommunityTarget v1target = new CommunityTarget();
        v1target.setCommunity(new OctetString(_community)); // community is important
        v1target.setRetries(1); // if possible, retry this request
        v1target.setTimeout(5000); // the timeout in mills for one pdu
        v1target.setVersion(SnmpConstants.version1);
        v1target.setAddress(address);

        PDUv1 v1pdu = new PDUv1();
        v1pdu.setType(PDU.GET);
        v1pdu.addAll(_requestVbs);
        responseEvent = _snmp.get(v1pdu, v1target);
        _printResponse(responseEvent);

    }


    private static void _printResponse(ResponseEvent responseEvent) {
        PDU responsePDU = responseEvent.getResponse();
        if (responsePDU == null) {
            System.out.println("No response found, maybe snmp v3 related args found wrong");
        }
        else {
            if (responsePDU.getErrorIndex() != 0 ) {
                System.out.println("Error found " + responsePDU);
                System.out.println("Request oids are " + responseEvent.getRequest().getVariableBindings());
                System.out.println("Error index = " + responsePDU.getErrorIndex() + " errorMsg=" + responsePDU.getErrorStatusText());
            }
            else {
                System.out.println("No error index found");
                System.out.println("Host name is - " + responsePDU.get(0).getVariable() + " isException=" + responsePDU.get(0).getVariable().isException());
                System.out.println("Not exist oid is - " + responsePDU.get(1).getVariable() + " isException=" + responsePDU.get(1).getVariable().isException());
                System.out.println("Uptime is - " + responsePDU.get(2).getVariable() + " isException=" + responsePDU.get(2).getVariable().isException());
            }
        }
    }

    public static void _compareWrongCredentials() {

    }


    private static void _printUsage() {
        System.out.println("Arguments error. " + CompareDifferentVersion.class.getName() + " [remote device Ip, remote device port, community, security, authProtocol, authToken, privProtocol, privToken]");
        System.out.println("security is the user name");
        System.out.println("authProtocol is the authentication protocol, now support MD5 and SHA");
        System.out.println("authToken is the authentication passphrase");
        System.out.println("privProtocol is the privacy protocol, now support DES/AES/AES128/3DES/AES256/AES384 (some may be restricted by jdk)");
        System.out.println("privToken is the privacy passpharse");
    }

}
