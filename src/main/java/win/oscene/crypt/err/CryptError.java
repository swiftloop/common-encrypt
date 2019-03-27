package win.oscene.crypt.err;

/**
 * @author Sorata  2019-03-25 10:57
 */
public class CryptError extends RuntimeException {


    public CryptError() {
    }

    public CryptError(String message) {
        super(message);
    }
}
