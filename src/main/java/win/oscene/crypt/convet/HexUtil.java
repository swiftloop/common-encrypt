package win.oscene.crypt.convet;

import win.oscene.crypt.err.CryptError;
import win.oscene.crypt.err.CryptNullError;


/**
 * @author Sorata
 *
 * time: 2019-03-25 09:57:43
 */
public class HexUtil {

    // do not init
    private HexUtil(){}


    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_LOWER =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * Used to build output as Hex
     */
    private static final char[] DIGITS_UPPER =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};



    /**
     *  一个字节 0XFF
     *  |高位  低位|
     *  |1111 1111|
     *  字节数组转char，取高位 & 0XF0 即 1111 0000 将低位置为0000再
     *  将其右移 >>> 4 抹去低位 留高位 ，然后用该字节 & 0X0F 即 0000 1111 将高位置0 留低位
     *  此时 将一个字节拆成了 1111 和 1111 两个整形
     *
     * @param bytes 需要转化的字节数组
     * @return char
     */
    public static char[] toChars(final byte[] bytes, final char[] transform){
        if (bytes == null || bytes.length == 0){
            return new char[0];
        }
        char[] chs = new char[bytes.length << 1];
        int j = 0;
        for (byte b : bytes){
            chs[j++] = transform[(b & 0xF0) >>> 4];
            chs[j++] = transform[(b & 0x0F)];
        }
        return chs;
    }


    /**
     * 取两个字符串 这两个是encode时将一个字节拆分出来的，此时 将两个字节 前面的是高位  高位左移 4 将其升为高位再
     * 或 |  一个低位 即将低位合并
     * @param chars 字节数组转化过来的 char数组
     * @return 字节数组
     */
    public static byte[] toBytes(final char[] chars){
        if (chars == null || chars.length == 0){
            throw new CryptNullError("获取的字符数组为空");
        }
        if ((chars.length & 0x01) !=0){
           throw new CryptError("非法的字符数组");
        }
        byte[] bytes = new byte[chars.length >> 1];
        int j =0;
        for (int i = 0; j < chars.length; i++) {
            int m = digit(chars[j],j) << 4;
            j++;
            int n = m | digit(chars[j],j);
            j++;
            bytes[i] = (byte) (n & 0xff);
        }
        return bytes;
    }



    private static int digit(final char c,final int index){
        int m = Character.digit(c,16) ;
        if (m == -1){
            throw new CryptError("不能获取正确的字符"+ c + " 位置为："+ index);
        }
        return m;
    }




    public static String encode(final byte[] bytes,boolean lower){
        return new String(toChars(bytes,lower? DIGITS_LOWER : DIGITS_UPPER ));
    }

    public static String encodeNormal(final byte[] bytes){
        return encode(bytes,true);
    }

    public static byte[] decode(final String str){
        return toBytes(str.toCharArray());
    }

}
