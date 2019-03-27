package win.oscene.crypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Sorata  2019-03-26 15:26
 */
public class RSA {


    private static final String RSA_TYPE = "RSA";


    public enum SignType{
        RSA("SHA1withRSA"),
        RSA2("SHA256withRSA");

        private String type;
        SignType(String type){
            this.type = type;
        }

        public String getType() {
            return type;
        }
    }



    // do not init
    private RSA(){}


    public static byte[] encode(final byte[] origin, final byte[] publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_TYPE);
        PublicKey aPublic = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance(RSA_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE,aPublic);
        cipher.update(origin);
        return cipher.doFinal();

    }

    public static byte[] decode(final byte[] origin,final byte[] privateKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_TYPE);
        PrivateKey aPrivate = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance(RSA_TYPE);
        cipher.init(Cipher.DECRYPT_MODE,aPrivate);
        cipher.update(origin);
        return cipher.doFinal();
    }



    public static byte[] sign(final byte[] origin,final byte[] privateKey,String signType) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_TYPE);
        PrivateKey aPrivate = keyFactory.generatePrivate(encodedKeySpec);
        Signature signature = Signature.getInstance(signType);
        signature.initSign(aPrivate);
        signature.update(origin);
        return signature.sign();
    }



    public static boolean verify(final byte[] origin, final byte[] sign,final byte[] publicKey,String signType) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_TYPE);
        PublicKey aPublic = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance(signType);
        signature.initVerify(aPublic);
        signature.update(origin);
        return signature.verify(sign);
    }



}
