import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;



public class SessionKey {
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
        KeyGen.init(keylength);
        this.secretKey = KeyGen.generateKey();
    }

    public SessionKey(String encodedkey){
      byte[] Base64Key = Base64.getDecoder().decode(encodedkey);
      this.secretKey = new SecretKeySpec(Base64Key,0,Base64Key.length, "AES");
      }

      public SessionKey(byte[] Key) {
        this.secretKey = new SecretKeySpec(Key,"AES");
      }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }

}
