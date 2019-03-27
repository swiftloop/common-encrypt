package win.oscene.crypt;

public enum DigestType{

    MD5("MD5"),
    SHA1("SHA"),
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512")
    ;


    private String type;

    DigestType(String type){
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
