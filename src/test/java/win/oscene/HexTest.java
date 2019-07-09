package win.oscene;

import org.junit.Assert;
import org.junit.Test;
import win.oscene.crypt.*;
import win.oscene.crypt.convet.Base64;
import win.oscene.crypt.convet.HexUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;



public class HexTest {

    @Test
    public void TestHex2String() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        System.out.println(122 & 0xff);
        System.out.println(Integer.toHexString(16));
        System.out.println((int)'M');
        System.out.println(Integer.toHexString(77));

        System.out.println(Integer.toBinaryString(240));
        System.out.println(Integer.toBinaryString(15));


        System.out.println(HexUtil.encodeNormal(HMac.encode("123456","123456", Charset.forName("UTF-8"), HmacType.HmacSHA256)));

        System.out.println(HexUtil.encodeNormal(AES.encode("123456".getBytes(StandardCharsets.UTF_8),"9f13ec2c5d3aacc9e5292648b0f9f1c1".getBytes(StandardCharsets.UTF_8))));
        System.out.println(new String(AES.decode(HexUtil.decode("33b0d0b8d05d9b9762b2eff0d3942b03"),"9f13ec2c5d3aacc9e5292648b0f9f1c1".getBytes(StandardCharsets.UTF_8))));

    }

    @Test
    public void aesTest() throws Exception {

        String origin = "123456";
        String key = HexUtil.encodeNormal(KeyFactory.createAesKey(128));
        System.out.println("AES测试开始  待加密的字符串为:" + origin  + "  生成的密钥为:"+ key);
        String encodeStr = HexUtil.encodeNormal(AES.encode(origin.getBytes(StandardCharsets.UTF_8),HexUtil.decode(key)));
        System.out.println("加密后的字符串为：" + encodeStr);
        String decodeStr = new String(AES.decode(HexUtil.decode(encodeStr),HexUtil.decode(key)));
        System.out.println("解密后与原字符串是否相等："+ origin.equals(decodeStr));

        //  convet encode | decode
        String keyBase64 = Base64.encode(KeyFactory.createAesKey(128));
        String encodeHex = XDigest.aesEncodeHex(origin,keyBase64);
        Assert.assertEquals(XDigest.aesDecodeHex(encodeHex,keyBase64),origin);
        //  base64 encode | decode
        String encodeBase64 = XDigest.aesEncodeBase64(origin,keyBase64);
        Assert.assertEquals(XDigest.aesDecodeBase64(encodeBase64,keyBase64),origin);

    }

    @Test
    public void md5AndShaTest(){
        String origin = "123456";
        String md5 = "e10adc3949ba59abbe56e057f20f883e";
        System.out.println("Md5加密：" + XDigest.md5(origin,true).equals(md5));
        Assert.assertEquals(XDigest.md5(origin,false),md5);

        System.out.println("sha1:" + XDigest.sha(origin,DigestType.SHA1,false));
        System.out.println("sha224:" + XDigest.sha(origin,DigestType.SHA224,false));
        System.out.println("sha256:" + XDigest.sha(origin,DigestType.SHA256,false));
        System.out.println("sha384:" + XDigest.sha(origin,DigestType.SHA384,false));
        System.out.println("sha512:" + XDigest.sha(origin,DigestType.SHA512,false));

    }

    @Test
    public void macTest(){

        String origin = "123456";
        String key = "123456";
        System.out.println("mac md5: "+ XDigest.hmacHex(origin,"123456",HmacType.HmacMD5));
        System.out.println("mac md5: "+ XDigest.hmacHex(origin,key,HmacType.HmacMD5));
        System.out.println("mac sha1: "+ XDigest.hmacHex(origin,key,HmacType.HmacSHA1));
        System.out.println("mac sha256: "+ XDigest.hmacHex(origin,key,HmacType.HmacSHA256));
        Assert.assertEquals("74b55b6ab2b8e438ac810435e369e3047b3951d0", XDigest.hmacHex(origin,key,HmacType.HmacSHA1));

    }

    @Test
    public void keyfactory() throws Exception {
        System.out.println(HexUtil.encodeNormal(KeyFactory.createAesKey(128)));
        System.out.println(KeyFactory.createRandomKey(42,true));
        System.out.println(KeyFactory.createRandomKey(64,false));
    }





    @Test
    public void rsaTest() throws NoSuchAlgorithmException {
        byte[][] rsaKey = KeyFactory.createRSAKey(2048);
        byte[] privateKey = rsaKey[0];
        byte[] publicKey = rsaKey[1];
        System.out.println("私钥为 :" +Base64.encode(privateKey) +" \n");
        System.out.println("公钥为 :" +Base64.encode(publicKey) +" \n");

        String origin = "Hello world";
        // rsa encode
        System.out.println("即将加密的字符串为:" + origin);
        String s = XDigest.rsaEncodeHex(origin, Base64.encode(publicKey));
        System.out.println("采用hex编码的密文为: "+ s);

        String s1 = XDigest.rsaDecodeHex(s, Base64.encode(privateKey));
        System.out.println("解密后的原文为： "+ s1);
        Assert.assertEquals(origin,s1);


        String s2 = XDigest.rsaEncodeBase64(origin, Base64.encode(publicKey));
        System.out.println("采用base64编码的密文为: "+ s2);
        String s3 = XDigest.rsaDecodeBase64(s2, Base64.encode(privateKey));
        System.out.println("解密后的原文为： "+ s3);
        Assert.assertEquals(origin,s3);

        String s4 = XDigest.rsaSignHex(origin, Base64.encode(privateKey), RSA.SignType.RSA2);
        System.out.println("签名后采用hex编码:"+ s4);
        Assert.assertTrue(XDigest.rsaVerifyHex(origin,s4,Base64.encode(publicKey), RSA.SignType.RSA2));

        String s5 = XDigest.rsaSignBase64(origin, Base64.encode(privateKey), RSA.SignType.RSA);
        System.out.println("签名后采用Base64编码: "+ s5);
        Assert.assertTrue(XDigest.rsaVerifyBase64(origin,s5,Base64.encode(publicKey), RSA.SignType.RSA));


    }



}
