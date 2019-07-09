package win.oscene;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import win.oscene.crypt.KeyFactory;
import win.oscene.crypt.XDigest;
import win.oscene.crypt.convet.Base64;
import win.oscene.crypt.convet.HexUtil;

import java.security.NoSuchAlgorithmException;


public class DigestTest {


    private byte[] key;

    @Before
    public void init(){
        try {
            key = KeyFactory.createAesKey(256);
            System.out.println(HexUtil.encodeNormal(key));
            System.out.println(new String(HexUtil.decode(HexUtil.encode(key,false))));
            System.out.println(Base64.encode(key));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    @Test
    public void aesTest() throws NoSuchAlgorithmException {
        String origin = "{\"code\":\"hello UI hohadhaoihduhuegugduagudguagiuegudahdhuwuoaugsaalo280103701y8hdhiod#!3441231\"}";
        String k = "1234567890qwerty";
        String encode = XDigest.aesEncodeHex(origin, Base64.encode(key));
        System.out.println(encode);
        String n = XDigest.aesDecodeHex(encode,Base64.encode(key));
        Assert.assertEquals(origin,n);


        byte[][] rsaKey = KeyFactory.createRSAKey(2048);
        String encodeRsa = XDigest.rsaEncodeHex(origin,Base64.encode(rsaKey[1]));
        System.out.println(encode);
        String decodeHex = XDigest.rsaDecodeHex(encodeRsa, Base64.encode(rsaKey[0]));
        System.out.println(decodeHex);
        Assert.assertEquals(origin,decodeHex);

    }



}
