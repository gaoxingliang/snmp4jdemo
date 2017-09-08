package demo;

import org.snmp4j.smi.OID;

/**
 * define some constants which will be used
 *
 * Created by edward.gao on 07/09/2017.
 */
public class Constants {

    /**
     * the default community for most snmp agents
     */
    public static final String DEFAULT_COMMUNITY = "public";

    /**
     * the md5 authentication protocol
     */
    public static final String V3_AUTH_PROTOCOL_MD5 = "md5";

    /**
     * the sha authentication protocol
     */
    public static final String V3_AUTH_PROTOCOL_SHA = "sha";


    /**
     * the host name OID
     * <a href>http://www.alvestrand.no/objectid/1.3.6.1.2.1.1.html</a>
     */
    public static final OID OID_HOSTNAME = new OID("1.3.6.1.2.1.1.5.0");
    public static final OID OID_UPTIME = new OID("1.3.6.1.2.1.1.3.0");

}
