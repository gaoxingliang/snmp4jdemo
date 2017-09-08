package demo.examples;

import demo.Constants;
import demo.DebuggerLogFactory;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * test a snmp get request by using snmp v2c (community version)
 * Created by edward.gao on 07/09/2017.
 */
public class TestSnmpGetV2c {

    /**
     * Send a snmp get v2 request to request the remote device host name and uptime
     * @param args  [remote device Ip, remote device port, community]
     *
     *              Example: 192.168.170.149 161 public
     */
    public static void main(String[] args) throws Exception {
        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());

        if (args.length < 3) {
            _printUsage();
            return;
        }

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String community = args[2];
        System.out.println(String.format("Send message version 2 to %s:%d with community - %s", ip, port, community));
        Snmp snmp = new Snmp(new DefaultUdpTransportMapping());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.listen();

        CommunityTarget target = new CommunityTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setCommunity(new OctetString(community)); // community is important
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(5000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version1);

        PDU pdu = new PDU();
        pdu.setType(PDU.GET);
        //we can send more than one oid in a signle pdu request
        pdu.addOID(new VariableBinding(Constants.OID_HOSTNAME));
        pdu.addOID(new VariableBinding(Constants.OID_UPTIME));

        ResponseEvent responseEvent = snmp.get(pdu, target);
        PDU responsePDU = responseEvent.getResponse();
        if (responsePDU == null) {
            System.out.println("No response found, maybe community wrong");
        }
        else {
            if (responsePDU.getErrorIndex() != 0 ) {
                System.out.println("Error found " + responsePDU);
            }
            else {
                System.out.println("Host name is - " + responsePDU.get(0).getVariable());
                System.out.println("Uptime is - " + responsePDU.get(1).getVariable());
            }
        }
    }

    private static void _printUsage() {
        System.out.println("Arguments error. TestSnmpGetV2c [ip] [port] [community]");
    }
}
