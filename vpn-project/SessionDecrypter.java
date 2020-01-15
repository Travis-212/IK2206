import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static javax.crypto.Cipher.*;

public class SessionDecrypter {
    private SessionKey Sessiondec;
    private IvParameterSpec Ivectordec;
    private Cipher cipher;

    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher = getInstance("AES/CTR/NoPadding");
        this.Sessiondec = new SessionKey(key);
        this.Ivectordec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.cipher.init(Cipher.DECRYPT_MODE, this.Sessiondec.getSecretKey(),this.Ivectordec);
    }

    public SessionDecrypter(SessionKey sKey, IvParameterSpec sIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.Sessiondec = sKey;
        this.Ivectordec = sIV;
        this.cipher = getInstance("AES/CTR/NoPadding");
        this.cipher.init(Cipher.DECRYPT_MODE, this.Sessiondec.getSecretKey(),this.Ivectordec);
    }

    public CipherInputStream openCipherInputStream(InputStream input){
        CipherInputStream openCipherInputSteam = new CipherInputStream(input,cipher);
        return openCipherInputSteam;
    }
}
