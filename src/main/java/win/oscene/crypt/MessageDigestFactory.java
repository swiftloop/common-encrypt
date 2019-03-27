package win.oscene.crypt;

import win.oscene.crypt.err.CryptNullError;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestFactory {

    // do not init
    private MessageDigestFactory(){}

    /** 得到摘要算法的实例
     * @param type 摘要算法的类型 {@link DigestType}
     * @return MessageDigest
     */
    public static MessageDigest create(DigestType type){
        try {
            return MessageDigest.getInstance(type.getType());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 按照自定的消息摘要算法 进行加密
     * @param str 原始字符
     * @param digestType 加密类型
     * @param charset 指定的编码
     * @return byte[]
     */
    public static byte[] digest(String str, DigestType digestType, Charset charset){
        MessageDigest digest = MessageDigestFactory.create(digestType);
        if (digest == null){
            throw new CryptNullError("获取到的摘要算法为空");
        }
        digest.update(str.getBytes(charset));
        return digest.digest();
    }




}
