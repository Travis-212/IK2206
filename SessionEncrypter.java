import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static javax.crypto.Cipher.*;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private IvParameterSpec Ivector;
    private Cipher cipher;

    public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.sessionKey = new SessionKey(keylength);
        this.cipher = getInstance("AES/CTR/NoPadding");
        byte [] BlockByte = new byte[cipher.getBlockSize()];
        SecureRandom RVal = new SecureRandom();
        RVal.nextBytes(BlockByte);

        this.Ivector = new IvParameterSpec(BlockByte);
        this.cipher.init(ENCRYPT_MODE,sessionKey.getSecretKey(),Ivector);
    }
  
    public SessionEncrypter(SessionKey skey, IvParameterSpec sIV) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        this.sessionKey = skey;
        this.Ivector = sIV;
        this.cipher = getInstance("AES/CTR/NoPadding");
        this.cipher.init(ENCRYPT_MODE,sessionKey.getSecretKey(),Ivector);
    }

    public String encodeKey() {return this.sessionKey.encodeKey();}

    public String encodeIV(){return Base64.getEncoder().encodeToString(Ivector.getIV());}

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        CipherOutputStream openCipherOutputsteam = new CipherOutputStream(output, cipher);
        return openCipherOutputsteam;

    }
}
