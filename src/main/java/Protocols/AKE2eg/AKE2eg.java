package Protocols.AKE2eg;

import Certifications.Cert;
import Encrypt.DH;
import Encrypt.Digest;
import Encrypt.HKDF;
import Encrypt.Utils;

import java.security.KeyPair;
import java.security.PublicKey;

public class AKE2eg {
    static int keySize = 32;
    static String preString = "[AKE2eg]:";
    public static class Client{
        static String prePreString = "Client:";
        static StringBuffer logBuffer = new StringBuffer();
        public static KeyPair keyPairDH;
        public static KeyPair keyPairDigest;
        static byte[] key = new byte[keySize];

        static {
            try {
                keyPairDH = DH.generateKeyPair(); //Диффи
                keyPairDigest = Digest.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("001", keyPairDigest.getPublic());

        public static void startSession(){
            boolean check = SendCert();
            if (check){
                logBuffer.append(preString + prePreString+ "Successful!!! Key is " + Utils.bytesToHex(key) + "\n");
            } else {
                logBuffer.append(preString + prePreString+ "Aborted" + "\n");
            }
        }

        public static boolean SendCert(){
            byte[] signU = new byte[0];
            try {
                signU = Digest.signData(keyPairDH.getPublic().getEncoded(), keyPairDigest.getPrivate()); //подпись
            } catch (Exception e) {
                e.printStackTrace();
            }
            logBuffer.append(preString + prePreString+ "Send to Server: signU - " + Utils.bytesToHex(signU) + ", \\\nCert - {id}:"
                    + cert.getId() + "\t {pub key}" + Utils.bytesToHex(cert.getKey().getEncoded()) + "\n" + "u: " + Utils.bytesToHex(keyPairDH.getPublic().getEncoded()));

            AKE2EgResponse ake2EgResponse = Server.getCert(keyPairDH.getPublic(), signU, cert);
            if (ake2EgResponse == null){
                return false;
            }
            logBuffer.append(preString + prePreString+ "Get from Server: c - " + Utils.bytesToHex(ake2EgResponse.c.getEncoded()) + ", \\\nCert - {id}:"
                    + ake2EgResponse.cert.getId() + "\t {pub key}" + Utils.bytesToHex(ake2EgResponse.cert.getKey().getEncoded()) + "\\\n" +
                    "Sign: " + Utils.bytesToHex(ake2EgResponse.sig) + "\n");

            return checkAnswer(ake2EgResponse);
        }

        public static boolean checkAnswer(AKE2EgResponse ake2EgResponse){
            String idQ = ake2EgResponse.cert.getId();
            try {
                if (!Digest.checkSign(ake2EgResponse.sig, Utils.concatArrays(keyPairDH.getPublic().getEncoded(), ake2EgResponse.c.getEncoded(), cert.getId().getBytes()), ake2EgResponse.cert.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return false;
                }

                byte[] keyData = DH.doDH(keyPairDH.getPrivate(), ake2EgResponse.c);
                logBuffer.append(preString + prePreString+ "DH Key is " + Utils.bytesToHex(keyData) + "\n");

                key = HKDF.getKey(Utils.concatArrays(keyPairDH.getPublic().getEncoded(), ake2EgResponse.c.getEncoded(), keyData, ake2EgResponse.cert.getId().getBytes()));
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
        public static KeyPair keyPairDH;
        public static KeyPair keyPairDigest;
        static byte[] key;

        static {
            try {
                keyPairDH = DH.generateKeyPair();
                keyPairDigest = Digest.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("002", keyPairDigest.getPublic());


        public static AKE2EgResponse getCert(PublicKey u, byte[] signU, Cert certClient){
            logBuffer.append(preString + prePreString+ "Get from Client: u - " + Utils.bytesToHex(u.getEncoded()) + ", \\\nCert - {id}:"
                    + certClient.getId() + "\t {pub key}" + Utils.bytesToHex(certClient.getKey().getEncoded()) + "\n");
            boolean checkSign = false;
            try {
                checkSign = Digest.checkSign(signU, u.getEncoded(), certClient.getKey());
            } catch (Exception e) {
                e.printStackTrace();
            }
            logBuffer.append(preString + prePreString+ "Check sign: " + Utils.bytesToHex(signU) + ":"
                    + checkSign + "\n");
            if (!checkSign){
                logBuffer.append(preString + prePreString+ "Failed check sign. Abort..." + "\n");
                return null;
            }


            byte[] keyData;
            try {
                keyData = DH.doDH(keyPairDH.getPrivate(), u); //key evaluate
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
            logBuffer.append(preString + prePreString+ "Evaluate DH key: " + Utils.bytesToHex(keyData) + "\n");

            key = HKDF.getKey(Utils.concatArrays(u.getEncoded(), keyPairDH.getPublic().getEncoded(), keyData, cert.getId().getBytes()));
            logBuffer.append(preString + prePreString+ "Evaluate HKDF key: " + Utils.bytesToHex(key) + "\n");
            PublicKey c = null;
            try {
                c = keyPairDH.getPublic(); //Открытый ключ DH

            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] sign = new byte[0];
            try {
                assert c != null;
                sign = Digest.signData(Utils.concatArrays(u.getEncoded(), c.getEncoded(), certClient.getId().getBytes()), keyPairDigest.getPrivate()); //Подписываем
                //sign = Digest.signData(Utils.concatArrays(u.getEncoded(), c.getEncoded(), "123".getBytes()), keyPairDigest.getPrivate()); //Error. Warning. Server sign idClient incorrect
            } catch (Exception e) {
                e.printStackTrace();
            }


            return new AKE2EgResponse(c, sign, cert);
        }
        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static void main(String[] args) {
        Client.startSession();
        Client.printLogger();
        Server.printLogger();
    }
}
