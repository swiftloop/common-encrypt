package win.oscene.crypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Sorata  2019-03-26 10:57
 */
public class AES {


    private static final String Algorithm = "AES";


    // do not init
    private AES() {
    }


    /**
     * * <ul>
     * * <li><tt>AES/CBC/NoPadding</tt> (128)</li>
     * * <li><tt>AES/CBC/PKCS5Padding</tt> (128)</li>
     * * <li><tt>AES/ECB/NoPadding</tt> (128)</li>
     * * <li><tt>AES/ECB/PKCS5Padding</tt> (128)</li>
     *
     * @param str
     * @param key
     * @return
     */
    public static byte[] encode(final byte[] str, final byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec keySpec = new SecretKeySpec(key, Algorithm);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        cipher.update(str);
        return cipher.doFinal();
    }




    public static byte[] decode(final byte[] str, final byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKeySpec keySpec = new SecretKeySpec(key, Algorithm);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        cipher.update(str);
        return cipher.doFinal();


    }


}
