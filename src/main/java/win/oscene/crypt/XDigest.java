package win.oscene.crypt;

import win.oscene.crypt.convet.Base64;
import win.oscene.crypt.convet.HexUtil;
import win.oscene.crypt.err.CryptError;

import java.nio.charset.Charset;



/**
 * @author Sorata  2019-03-26 14:02
 */
public final class XDigest {


    /**
     * 默认的编码
     */
    public static Charset charset = Charset.forName("UTF-8");

    // Do not init
    private XDigest() {
    }


    /**
     * md5 加密
     *
     * @param origin 加密的原文
     * @param base64 是否采用base64编码
     * @return 密文
     */
    public static String md5(final String origin, boolean base64) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        byte[] digest = MessageDigestFactory.digest(origin, DigestType.MD5, charset);
        return base64 ? Base64.encode(digest) : HexUtil.encodeNormal(digest);
    }

    /**
     * 转hex编码的md5加密
     *
     * @param origin 加密的原文
     * @return 密文
     */
    public static String md5Hex(final String origin) {
        return md5(origin, false);
    }

    /**
     * 转base64编码的md5加密
     *
     * @param origin 加密的原文
     * @return 密文
     */
    public static String md5Base64(final String origin) {
        return md5(origin, true);
    }


    /**
     * sha 加密
     *
     * @param origin     加密原文
     * @param digestType 加密的算法 需要排除掉MD5
     * @param base64     是否采用base64编码
     * @return 密文
     */
    public static String sha(final String origin, DigestType digestType, boolean base64) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (digestType == DigestType.MD5) {
            throw new CryptError("请使用正确的sha算法");
        }
        byte[] digest = MessageDigestFactory.digest(origin, digestType, charset);
        return base64 ? Base64.encode(digest) : HexUtil.encodeNormal(digest);
    }

    /**
     * 转hex编码的 sha加密
     *
     * @param origin     加密为原文
     * @param digestType 算法  需要排除md5
     * @return 密文
     */
    public static String shaHex(final String origin, DigestType digestType) {
        return sha(origin, digestType, false);
    }

    /**
     * 转base64编码的 sha加密
     *
     * @param origin     加密为原文
     * @param digestType 算法  需要排除md5
     * @return 密文
     */
    public static String shaBase64(final String origin, DigestType digestType) {
        return sha(origin, digestType, true);
    }

    /**
     * hmac加密
     *
     * @param origin   加密的原文
     * @param key      加密的key
     * @param hmacType 加密的算法
     * @param base64   是否采用base64
     * @return 密文
     */
    public static String hmac(final String origin, final String key, HmacType hmacType, boolean base64) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (key == null || key.length() == 0) {
            throw new CryptError("参与mac加密的密钥不能为空");
        }
        try {
            byte[] encode = HMac.encode(origin, key, charset, hmacType);
            return base64 ? Base64.encode(encode) : HexUtil.encodeNormal(encode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 采用hex编码的hmac加密
     *
     * @param origin   原文
     * @param key      加密的密钥
     * @param hmacType 算法
     * @return 密文
     */
    public static String hmacHex(final String origin, final String key, HmacType hmacType) {
        return hmac(origin, key, hmacType, false);
    }


    /**
     * 采用base64编码的hmac加密
     *
     * @param origin   原文
     * @param key      加密的密钥
     * @param hmacType 算法
     * @return 密文
     */
    public static String hmacBase64(final String origin, final String key, HmacType hmacType) {
        return hmac(origin, key, hmacType, true);
    }

    /**
     * aes 加密算法
     *
     * @param origin    原文
     * @param key       参与签名的key key的长度需要是 128位 可以使用 {@link KeyFactory}  生成密钥
     * @param base64    返回的结果是否采用base64编码 {@code false  将转化Hex}
     * @param base64Key 对key的编码方式  base64 | convet
     * @return 密文
     */
    public static String aesEncode(final String origin, final String key, boolean base64, boolean base64Key) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (key == null || key.length() == 0) {
            throw new CryptError("参与AES加密的密钥不能为空");
        }
        try {
            byte[] encode = AES.encode(origin.getBytes(charset), base64Key ? Base64.decode(key) : HexUtil.decode(key));
            return base64 ? Base64.encode(encode) : HexUtil.encodeNormal(encode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 结果使用hex进行编码  而参与加密的密钥是采用 base64编码的字符串
     *
     * @param origin 原文
     * @param key    base64编码的128位的密钥
     * @return 密文
     */
    public static String aesEncodeHex(final String origin, final String key) {
        return aesEncode(origin, key, false, true);
    }


    /**
     * 结果使用hex进行编码  而参与加密的密钥是采用 base64编码的字符串
     *
     * @param origin 原文
     * @param key    base64编码的128位的密钥
     * @return 密文
     */
    public static String aesEncodeBase64(final String origin, final String key) {
        return aesEncode(origin, key, true, true);
    }

    /**
     * aes 解密
     * @param origin 原文
     * @param key 参与签名的key key的长度需要是 128位 可以使用 {@link KeyFactory}  生成密钥
     * @param base64 加密的时候是否采用的是base64编码转换的String
     * @param base64Key 对key的编码方式  base64 | convet
     * @return 密文
     */
    public static String aesDecode(final String origin, final String key, boolean base64, boolean base64Key){
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (key == null || key.length() == 0) {
            throw new CryptError("参与AES解密的密钥不能为空");
        }

        try {
            byte[] decode = AES.decode(base64 ? Base64.decode(origin) : HexUtil.decode(origin), base64Key ? Base64.decode(key) : HexUtil.decode(key));
            return new String(decode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * aes的解密操作 解密的是hex编码的密文  key采用的base64编码的key
     * @param origin hex的密文
     * @param key base64编码的key
     * @return 原文
     */
    public static String aesDecodeHex(final String origin,final String key){
        return aesDecode(origin,key,false,true);
    }

    /**
     * aes的解密操作 解密的是base64编码的密文  key采用的base64编码的key
     * @param origin base64编码的密文
     * @param key base64编码的key
     * @return 原文
     */
    public static String aesDecodeBase64(final String origin,final String key){
        return aesDecode(origin,key,true,true);
    }

    /**
     * RSA 加密操作  这里一般是采用公钥加密 配对的私钥解密
     * @param origin 原文
     * @param key 公钥 采用hex | base64编码 可以使用{@link KeyFactory} 创建一对rsa密钥
     * @param base64 加密后的密文的编码形式是否采用base64   convet |  base64
     * @param base64Key 密钥采用的是否是base64编码的字符串
     * @return 密文
     */
    public static String rsaEncode(final String origin, final String key, boolean base64, boolean base64Key) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (key == null || key.length() == 0) {
            throw new CryptError("参与RSA加密的密钥不能为空");
        }
        try {
            byte[] encode = RSA.encode(origin.getBytes(charset), base64Key ? Base64.decode(key) : HexUtil.decode(key));
            return base64 ? Base64.encode(encode) : HexUtil.encodeNormal(encode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }


    /**
     * RSA 加密操作  这里生成hex编码的密文 而加密的密钥采用的base64编码的密钥
     * @param origin 原文
     * @param key base64　编码的密钥
     * @return 密文
     */
    public static String rsaEncodeHex(final String origin, final String key){
        return rsaEncode(origin,key,false,true);
    }

    /**
     * RSA 加密操作  这里生成base64编码的密文 而加密的密钥采用的base64编码的密钥
     * @param origin 原文
     * @param key base64　编码的密钥
     * @return 密文
     */
    public static String rsaEncodeBase64(final String origin, final String key){
        return rsaEncode(origin,key,true,true);
    }

    /**
     * RSA 解密操作  一般采用的是私钥解密  公钥加密
     * @param origin 公钥加密的密文
     * @param key 私钥 采用hex | base64编码 可以使用{@link KeyFactory} 创建一对rsa密钥
     * @param base64 加密的时候是否采用base64编码
     * @param base64Key 密钥采用的是否是base64编码的字符串
     * @return 原文
     */
    public static String rsaDecode(final String origin, final String key, boolean base64, boolean base64Key) {
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (key == null || key.length() == 0) {
            throw new CryptError("参与RSA解密的密钥不能为空");
        }
        try {
            byte[] decode = RSA.decode(base64 ? Base64.decode(origin) : HexUtil.decode(origin),
                    base64Key ? Base64.decode(key) : HexUtil.decode(key));
            return new String(decode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }


    /**
     * RSA解密操作  这里解密的是Hex编码的密文  base64编码的密钥
     * @param origin hex编码的密文
     * @param key base64编码的密钥
     * @return 原文
     */
    public static String rsaDecodeHex(final String origin,final String key){
        return rsaDecode(origin,key,false,true);
    }

    /**
     * RSA解密操作  这里解密的是base64编码的密文  base64编码的密钥
     * @param origin base64编码的密文
     * @param key base64编码的密钥
     * @return 原文
     */
    public static String rsaDecodeBase64(final String origin,final String key){
        return rsaDecode(origin,key,true,true);
    }

    /**
     * RSA签名的操作 这里是采用私钥签名  公钥验签
     * @param origin 参与签名的字符串
     * @param privateKey 私钥
     * @param base64 签名的结果是否采用base64编码
     * @param base64Key 签名的key是否是采用base64编码
     * @param type 签名的类型  {@link win.oscene.crypt.RSA.SignType}
     * @return 签名后的密文
     */
    public static String rsaSign(final String origin, final String privateKey, boolean base64, boolean base64Key, RSA.SignType type){
        if (origin == null || origin.length() == 0) {
            return "";
        }
        if (privateKey == null || privateKey.length() == 0) {
            throw new CryptError("参与RSA签名的密钥不能为空");
        }
        try {
            byte[] sign = RSA.sign(origin.getBytes(charset), base64Key ? Base64.decode(privateKey) : HexUtil.decode(privateKey),
                    type.getType());
            return base64 ? Base64.encode(sign) : HexUtil.encodeNormal(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * RSA  签名操作 这里采用的是hex编码的结果集  而密钥采用的base64编码的私钥
     * @param origin 签名的字符串
     * @param privateKey base64编码的私钥
     * @param type 签名的类型 {@link win.oscene.crypt.RSA.SignType}
     * @return 签名后的密文
     */
    public static String rsaSignHex(final String origin, final String privateKey, RSA.SignType type){
        return rsaSign(origin,privateKey,false,true,type);
    }


    /**
     * RSA  签名操作 这里采用的是base64编码的结果集  而密钥采用的base64编码的私钥
     * @param origin 签名的字符串
     * @param privateKey base64编码的私钥
     * @param type 签名的类型 {@link win.oscene.crypt.RSA.SignType}
     * @return 签名后的密文
     */
    public static String rsaSignBase64(final String origin, final String privateKey, RSA.SignType type){
        return rsaSign(origin,privateKey,true,true,type);
    }

    /**
     * RSA  验签操作 一般采用的是公钥验签 私钥加密
     * @param origin 签名的字符串
     * @param sign 签名好的密文
     * @param publicKey 签名的公钥
     * @param base64 签名时返回的结果集是否是采用base64编码
     * @param base64Key 签名的密钥是否是采用base64编码
     * @param signType 签名的类型 {@link win.oscene.crypt.RSA.SignType}
     * @return {@code true} success
     */
    public static boolean rsaVerify(final String origin, final String sign, final String publicKey, boolean base64, boolean base64Key, RSA.SignType signType){
        // 三者 任意一者为空则该校验没有任何意义
        if (origin == null || origin.length() == 0) {
            return false;
        }
        if (sign == null || sign.length() == 0){
            return false;
        }
        if (publicKey == null || publicKey.length() == 0) {
           return false;
        }

        try {
            return  RSA.verify(origin.getBytes(charset), base64 ? Base64.decode(sign) : HexUtil.decode(sign), base64Key ? Base64.decode(publicKey) :
                    HexUtil.decode(publicKey), signType.getType());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;

    }

    /**
     * RSA 签名的验证操作
     * @param origin 参与签名的字符串
     * @param sign 签名的密文 这里是采用Hex编码的密文
     * @param key 验证签名的公钥  这里是采用base64的公钥
     * @param type 签名的类型
     * @return {@link win.oscene.crypt.RSA.SignType}
     */
    public static boolean rsaVerifyHex(final String origin, final String sign,final String key, RSA.SignType type){
        return rsaVerify(origin,sign,key,false,true,type);
    }

    /**
     * RSA 签名的验证操作
     * @param origin 参与签名的字符串
     * @param sign 签名的密文 这里是采用base64编码的密文
     * @param key 验证签名的公钥  这里是采用base64的公钥
     * @param type 签名的类型
     * @return {@link win.oscene.crypt.RSA.SignType}
     */
    public static boolean rsaVerifyBase64(final String origin, final String sign,final String key, RSA.SignType type){
        return rsaVerify(origin,sign,key,true,true,type);
    }

}
