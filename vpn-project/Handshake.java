import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    //public static final String serverHost = "localhost";
    //public static final int serverPort = 4412;

    /* The final destination */
    //public static String targetHost = "localhost";
    //public static int targetPort = 6789;

    public static X509Certificate Clientcert;
    public static X509Certificate Servercert;

    public static String SessionHost;
    public static int SessionPort;

    public static String targetHost;
    public static int targetPort;

    public static SessionDecrypter SessionDecrypter;
    public static SessionEncrypter SessionEncrypter;


    public static void Handshake(Socket socket, String UserFile, String value) throws IOException, CertificateException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", value);
        HandMessage.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(UserFile).getEncoded()));
        HandMessage.send(socket);
    }

    public static void VerifyClientHello(Socket socket, String caFile) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
            if(HandMessage.getParameter("MessageType").equals("ClientHello")) {
                String UserCert = HandMessage.getParameter("Certificate");
                Clientcert = VerifyCertificate.createCertificate(UserCert);
                try{
                    VerifyCertificate.getVerify(VerifyCertificate.getCertificate(caFile),Clientcert);
                    Logger.log("Client Certificate Verification Succeeded");
                }
                catch(Exception E){
                    socket.close();
                    Logger.log("Error: Client Certificate Verification Failed");
                }
            }else{
                socket.close();
                Logger.log("MessageType Not Found!");
            }
    }

    public static void VerifyServerHello(Socket socket, String caFile) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("ServerHello")) {
            Logger.log("ServerHello phase running");
            String cCert = HandMessage.getParameter("Certificate");
            Servercert = VerifyCertificate.createCertificate(cCert);
            try{
                VerifyCertificate.getVerify(VerifyCertificate.getCertificate(caFile),Servercert);
                Logger.log("Server Verify Succeeded");
            }
            catch(Exception E){
                socket.close();
                Logger.log("Error: Server Certificate Verification Failed");
            }
        }else{
            socket.close();
            Logger.log("MessageType Not Found!");
        }
    }

    public static void Forward(Socket socket, String targetHost, String targetPort) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Forward");
        HandMessage.putParameter("TargetHost", targetHost);
        HandMessage.putParameter("TargetPort", targetPort);
        HandMessage.send(socket);
        Logger.log("Portforwarding Succeeded");
    }

    public static void VerifyForward(Socket socket) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = HandMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(HandMessage.getParameter("TargetPort"));
            Logger.log("Success with TargetHost: " + targetHost + " and TargetPort: " + targetPort);
        }else {
            socket.close();
        }
    }

    public static void Session(Socket socket, String serverHost, String server) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Session");
        SessionKey Skey = new SessionKey(128);
        IvParameterSpec sIV = new IvParameterSpec(new SecureRandom().generateSeed(16));

        PublicKey PublicUser = Clientcert.getPublicKey();

        HandMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(Skey.getSecretKey().getEncoded(), PublicUser)));
        HandMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sIV.getIV(), PublicUser)));

        SessionEncrypter = new SessionEncrypter(Skey,sIV);
        SessionDecrypter = new SessionDecrypter(Skey, sIV);
        // System.out.println(Skey.encodeKey());
        // System.out.println(Base64.getEncoder().encodeToString(sIV.getIV()));
        HandMessage.putParameter("SessionHost", serverHost);
        HandMessage.putParameter("SessionPort", server);
        HandMessage.send(socket);
    }

    public static void VerifySession(Socket socket, String PrivKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Session")){
            String sKey = HandMessage.getParameter("SessionKey");
            String sIV = HandMessage.getParameter("SessionIV");
            SessionHost = HandMessage.getParameter("SessionHost");
            SessionPort = Integer.parseInt(HandMessage.getParameter("SessionPort"));
            byte[] SessKeyDec = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sKey),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            byte[] SessIVDec = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sIV),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));

            SessionEncrypter = new SessionEncrypter(new SessionKey((SessKeyDec)), new IvParameterSpec(SessIVDec));
            SessionDecrypter = new SessionDecrypter(new SessionKey((SessKeyDec)), new IvParameterSpec(SessIVDec));
            // System.out.println(new SessionKey((SessKeyDec)).encodeKey());
            // System.out.println(Base64.getEncoder().encodeToString(new IvParameterSpec(SessIVDec).getIV()));
        } else{
            socket.close();
        }
    }

    public static String getTargetHost() { return targetHost; }

    public static int getTargetPort() { return targetPort; }

    public static String getSessionHost() { return SessionHost; }

    public static int getSessionPort() { return SessionPort; }

    public static SessionDecrypter getSessionDecrypter() { return SessionDecrypter; }

    public static SessionEncrypter getSessionEncrypter() { return SessionEncrypter; }

}
