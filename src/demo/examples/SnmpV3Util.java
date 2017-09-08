package demo.examples;

import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.smi.OID;

import java.util.HashMap;
import java.util.Map;

/**
 * provide some help functions
 * Created by edward.gao on 08/09/2017.
 */
public class SnmpV3Util {

    private static final Map<String /*auth protocol lower case*/, OID /*matched algorithm*/> _authProtocol2OID = new HashMap<>();
    private static final Map<String /*privacy protocol lower case*/, OID /*matched algorithm*/> _privProtocol2OID = new HashMap<>();

    static {
        _authProtocol2OID.put("md5", AuthMD5.ID);
        _authProtocol2OID.put("sha", AuthSHA.ID);

        _privProtocol2OID.put("des", PrivDES.ID);
        _privProtocol2OID.put("3des", Priv3DES.ID);
        _privProtocol2OID.put("aes", PrivAES128.ID);
        _privProtocol2OID.put("aes128", PrivAES128.ID);
        // some algs will be restricted by jdk export policy. JCE
        _privProtocol2OID.put("aes192", PrivAES192.ID);
        _privProtocol2OID.put("aes256", PrivAES256.ID);
    }

    /**
     *
     * @param authProtocol  md5 or sha
     * @return the authentication protocol MD5 or SHA or null, if it's empty, means no authentication
     * @throws IllegalArgumentException if not MD5 or SHA
     */
    public static OID getAuthProtocol(String authProtocol) {
        if (authProtocol.isEmpty()) {
            return null;
        }
        OID authProtocolOID = _authProtocol2OID.get(authProtocol.toLowerCase());
        if (authProtocolOID == null) {
            throw new IllegalArgumentException("Unknown authentication protocol - " + authProtocol);
        }
        return authProtocolOID;
    }


    /**
     *
     * @param privacyProtocol
     * @return the authentication protocol MD5 or SHA or null, if it's empty, means no authentication
     * @throws IllegalArgumentException if not MD5 or SHA
     */
    public static OID getPrivacyProtocol(String privacyProtocol) {
        if (privacyProtocol.isEmpty()) {
            return null;
        }
        OID privacyProtocolOID = _privProtocol2OID.get(privacyProtocol.toLowerCase());
        if (privacyProtocolOID == null) {
            throw new IllegalArgumentException("Unknown privacy protocol - " + privacyProtocol);
        }
        return privacyProtocolOID;
    }
}
