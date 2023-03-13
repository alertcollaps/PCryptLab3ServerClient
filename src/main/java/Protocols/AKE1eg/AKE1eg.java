package Protocols.AKE1eg;

import Certifications.Cert;
import Encrypt.*;

import java.security.*;

public class AKE1eg {
    static int keySize = 32;
    static String preString = "[AKE1eg]:";
    public static class Client{
        static String prePreString = "Client:";
        static StringBuffer logBuffer = new StringBuffer();
        public static KeyPair keyPairDig;
        static byte[] key = new byte[keySize];

        static {
            try {
                keyPairDig = DH.generateKeyPair(); //Диффи
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("001", keyPairDig.getPublic());

        public static void startSession(){
            boolean check = SendCert();
            if (check){
                logBuffer.append(preString + prePreString+ "Successful!!! Key is " + Utils.bytesToHex(key) + "\n");
            } else {
                logBuffer.append(preString + prePreString+ "Aborted" + "\n");
            }
        }

        public static boolean SendCert(){
            byte[] r = Utils.generateBytes();
            logBuffer.append(preString + prePreString+ "Send to Server: r - " + Utils.bytesToHex(r) + ", \\\nCert - {id}:"
                    + cert.getId() + "\t {pub key}" + Utils.bytesToHex(cert.getKey().getEncoded()) + "\n");

            AKE1EgResponse ake1EgResponse = Server.getCert(r, cert);
            logBuffer.append(preString + prePreString+ "Get from Server: c - " + Utils.bytesToHex(ake1EgResponse.c.getEncoded()) + ", \\\nCert - {id}:"
                    + ake1EgResponse.cert.getId() + "\t {pub key}" + Utils.bytesToHex(ake1EgResponse.cert.getKey().getEncoded()) + "\\\n" +
                    "Sign: " + Utils.bytesToHex(ake1EgResponse.sig) + "\n");

            return checkAnswer(ake1EgResponse, r);
        }

        public static boolean checkAnswer(AKE1EgResponse ake1EgResponse, byte[] r){
            String idQ = ake1EgResponse.cert.getId();
            try {
                if (!Digest.checkSign(ake1EgResponse.sig, Utils.concatArrays(r, ake1EgResponse.c.getEncoded(), cert.getId().getBytes()), ake1EgResponse.cert.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return false;
                }

                byte[] keyData = DH.doDH(keyPairDig.getPrivate(), ake1EgResponse.c);
                logBuffer.append(preString + prePreString+ "DH Key is " + Utils.bytesToHex(keyData) + "\n");

                key = HKDF.getKey(Utils.concatArrays(cert.getKey().getEncoded(), ake1EgResponse.c.getEncoded(), keyData, ake1EgResponse.cert.getId().getBytes()));
                return true;

            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static class Server{
        static String prePreString = "Server:";
        static StringBuffer logBuffer = new StringBuffer();
        public static KeyPair keyPairDig;
        public static KeyPair keyPairDigest;
        static byte[] key;

        static {
            try {
                keyPairDig = DH.generateKeyPair();
                keyPairDigest = Digest.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("002", keyPairDigest.getPublic());


        public static AKE1EgResponse getCert(byte[] r, Cert certClient){
            logBuffer.append(preString + prePreString+ "Get from Client: r - " + Utils.bytesToHex(r) + ", \\\nCert - {id}:"
                    + certClient.getId() + "\t {pub key}" + Utils.bytesToHex(certClient.getKey().getEncoded()) + "\n");
            byte[] keyData;
            try {
                keyData = DH.doDH(keyPairDig.getPrivate(), (PublicKey) certClient.getKey()); //
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
            logBuffer.append(preString + prePreString+ "Evaluate DH key: " + Utils.bytesToHex(keyData) + "\n");

            key = HKDF.getKey(Utils.concatArrays(certClient.getKey().getEncoded(), keyPairDig.getPublic().getEncoded(), keyData, cert.getId().getBytes()));
            logBuffer.append(preString + prePreString+ "Evaluate HKDF key: " + Utils.bytesToHex(key) + "\n");
            PublicKey c = null;
            try {
                c = keyPairDig.getPublic(); //Открытый ключ DH

            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] sign = new byte[0];
            try {
                assert c != null;
                sign = Digest.signData(Utils.concatArrays(r, c.getEncoded(), certClient.getId().getBytes()), keyPairDigest.getPrivate()); //Подписываем
                //sign = Digest.signData(Utils.concatArrays(r, c.getEncoded(), "123".getBytes()), keyPairDigest.getPrivate()); //Error. Warning
            } catch (Exception e) {
                e.printStackTrace();
            }


            return new AKE1EgResponse(c, sign, cert);
        }
        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static void main(String[] args) {
        AKE1eg.Client.startSession();
        AKE1eg.Client.printLogger();
        AKE1eg.Server.printLogger();
    }
}
