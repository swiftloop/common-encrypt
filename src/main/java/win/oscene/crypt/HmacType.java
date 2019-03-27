package win.oscene.crypt;

/**
 * @author Sorata  2019-03-26 10:43
 */
public enum  HmacType {

    HmacMD5("HmacMD5"),
    HmacSHA1("HmacSHA1"),
    HmacSHA256("HmacSHA256");

    private String type;
    HmacType(String type){
        this.type = type;
    }

    public String getType() {
        return type;
    }}
