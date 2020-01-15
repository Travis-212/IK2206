import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;

public class VerifyCertificate {

    
    public static X509Certificate getCertificate(String Certificate) throws IOException, CertificateException {
        InputStream inStream = null;
        X509Certificate cert;
        try {
            inStream = new FileInputStream(Certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert;
    }

    public static void getVerify(X509Certificate CA, X509Certificate User) throws Exception {
        try {
            CA.checkValidity();
            User.checkValidity();
            CA.verify(CA.getPublicKey());
            User.verify(CA.getPublicKey());
            System.out.println("Pass");
        }
        catch(Exception E){
            System.out.println("Fail");
            System.out.println(E.toString());
            throw new Exception();
        }

    }

    public static X509Certificate createCertificate(String Certificate) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte [] CertByte = java.util.Base64.getDecoder().decode(Certificate);
        InputStream inStrem = new ByteArrayInputStream(CertByte);
        return (X509Certificate) cf.generateCertificate(inStrem);
    }

    public static void main(String[] args) throws Exception {
       // if(args.length() < 2){
       // System.exit(-1);
       // }
        String CA = args[0];
        String user = args[1];

        System.out.println(getCertificate(CA).getSubjectDN());
        System.out.println(getCertificate(user).getSubjectDN());
        getVerify(getCertificate(CA), getCertificate(user));
    }

}
