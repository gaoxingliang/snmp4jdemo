package demo.examples.snmpwalk;

import demo.DebuggerLogFactory;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.Snmp;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.util.List;

/**
 * test a snmp walk request for snmp v1 and v2. no differences here.
 * you just need to call the
 * <pre>
 *     target.setVersion(SnmpConstants.version1)
 *     target.setVersion(SnmpConstants.version2c);
 * </pre>
 *
 *
 *
 * Created by edward.gao on 11/09/2017.
 */
public class TestSnmpWalkV1AndV2c {

    /**
     * Send a snmp walk v1 request to walk out all interfaces
     *
     * @param args [remote device Ip, remote device port, community, oid, getbulk]
     *             <p>
     *             Example: 192.168.170.149 161 public
     */
    public static void main(String[] args) throws Exception {
        System.setProperty(LogFactory.SNMP4J_LOG_FACTORY_SYSTEM_PROPERTY, DebuggerLogFactory.class.getCanonicalName());


        if (args.length < 5) {
            _printUsage();
            return;
        }

        String ip = args[0];
        int port = Integer.valueOf(args[1]);
        String community = args[2];
        String oid = args[3];
        boolean useBulk = args.length > 4 ? Boolean.valueOf(args[4]) : true;
        System.out.println("Use bulk - " + useBulk);
        if (!useBulk) {
            SNMP4JSettings.setNoGetBulk(true);
        }

        System.out.println(String.format("Send message version 1 to %s:%d with community - %s, oid - %s, bulkwalk - %s", ip, port, community, oid, useBulk));
        MessageDispatcherImpl messageDispatcher = new MessageDispatcherImpl();
        Snmp snmp = new Snmp(messageDispatcher, new DefaultUdpTransportMapping());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.listen();

        CommunityTarget target = new CommunityTarget();
        Address address = new UdpAddress(String.format("%s/%d", ip, port));
        target.setAddress(address);
        target.setCommunity(new OctetString(community));
        target.setRetries(1); // if possible, retry this request
        target.setTimeout(5000); // the timeout in mills for one pdu
        target.setVersion(SnmpConstants.version1);
        //target.setVersion(SnmpConstants.version2c);

        OID networkInterfaceRootOID = new OID("1.3.6.1.2.1.2.2.1.2");
        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> resultEvents = treeUtils.getSubtree(target, networkInterfaceRootOID);
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
        System.out.println("Arguments error. " + TestSnmpWalkV1AndV2c.class.getName() + " [ip] [port] [community]");
    }
}
