package win.oscene.crypt;




import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

/**
 * @author Sorata  2019-03-26 11:38
 */
public class KeyFactory {


    private static final String  CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static final String FLAGS = "!@#$%^&*()_+=-~|?><,.;";

    /**
     * 该填充模式 AES/ECB/PKCS5Padding 需要128位的密钥
     * @return byte[]
     * @throws NoSuchAlgorithmException 未找到加密的方式
     */
    public static byte[] createAesKey() throws NoSuchAlgorithmException {
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(128);
        SecretKey secretKey = aes.generateKey();
        return secretKey.getEncoded();
    }


    /**
     * 创建一个随机的字符串
     * @param size 需要的长度
     * @param addFlag 是否添加符号
     * @return 一个随机的字符串
     */
    public static String createRandomKey(int size,boolean addFlag){
        StringBuilder builder = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            if (addFlag){
                builder.append((CHARS+FLAGS).charAt(new Random().nextInt(CHARS.length() + FLAGS.length())));
            }else {
                builder.append(CHARS.charAt(new Random().nextInt(CHARS.length())));
            }
        }
        return builder.toString();
    }


    // size  1024 2048
    public static byte[][] createRSAKey(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(size);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        byte[][] bytes = new byte[2][];
        bytes[0] = privateKey.getEncoded();
        bytes[1] = publicKey.getEncoded();
        return bytes;
    }





}
