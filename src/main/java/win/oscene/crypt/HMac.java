package win.oscene.crypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Sorata  2019-03-26 10:38
 */
public class HMac {

    private HMac(){}

    public static byte[] encode(final String str, final String key, Charset charset,HmacType type) throws NoSuchAlgorithmException, InvalidKeyException {
            Mac mac = Mac.getInstance(type.getType());
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(charset), mac.getAlgorithm());
            mac.init(keySpec);
            return mac.doFinal(str.getBytes(charset));
    }





}
