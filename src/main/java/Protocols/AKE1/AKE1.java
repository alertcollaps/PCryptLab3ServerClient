package Protocols.AKE1;


import Certifications.Cert;
import Encrypt.Digest;
import Encrypt.RSA;
import Encrypt.Utils;

import java.security.KeyPair;
import java.util.Arrays;

public class AKE1 {
    static int keySize = 32;
    static String preString = "[AKE1]:";
    public static class Client{
        static String prePreString = "Client:";
        static StringBuffer logBuffer = new StringBuffer();
        public static KeyPair keyPairDig;
        static byte[] key = new byte[keySize];

        static {
            try {
                keyPairDig = RSA.generateKeyPair();
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

            AKE1Response ake1Response = Server.getCert(r, cert);
            logBuffer.append(preString + prePreString+ "Get from Server: c - " + Utils.bytesToHex(ake1Response.c) + ", \\\nCert - {id}:"
                    + ake1Response.cert.getId() + "\t {pub key}" + Utils.bytesToHex(ake1Response.cert.getKey().getEncoded()) + "\\\n" +
                    "Sign: " + Utils.bytesToHex(ake1Response.sig) + "\n");

            return checkAnswer(ake1Response, r);
        }

        public static boolean checkAnswer(AKE1Response ake1Response, byte[] r){
            String idQ = ake1Response.cert.getId();
            try {
                if (!Digest.checkSign(ake1Response.sig, Utils.concatArrays(r, ake1Response.c, cert.getId().getBytes()), ake1Response.cert.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return false;
                }
                byte[] decrMessage = RSA.decrypt(ake1Response.c, keyPairDig.getPrivate());

                byte[] idQByte = new byte[decrMessage.length - keySize];
                System.arraycopy(decrMessage, keySize, idQByte, 0,idQByte.length);
                if (!Arrays.equals(idQByte, idQ.getBytes())){
                    logBuffer.append(preString + prePreString+ "Failed check idServer:" + new String(idQByte) + "\n");
                    return false;
                }

                System.arraycopy(decrMessage, 0, key, 0, keySize);
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

        static {
            try {
                keyPairDig = Digest.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("002", keyPairDig.getPublic());


        public static AKE1Response getCert(byte[] r, Cert certClient){
            logBuffer.append(preString + prePreString+ "Get from Client: r - " + Utils.bytesToHex(r) + ", \\\nCert - {id}:"
                    + certClient.getId() + "\t {pub key}" + Utils.bytesToHex(certClient.getKey().getEncoded()) + "\n");
            byte[] keyData = Utils.generateBytes(keySize);
            logBuffer.append(preString + prePreString+ "Generate key: " + Utils.bytesToHex(keyData) + "\n");
            byte[] c = new byte[0];
            try {
                c = RSA.encrypt(Utils.concatArrays(keyData, cert.getId().getBytes()), certClient.getKey());
                //c = RSA.encrypt(Utils.concatArrays(keyData, "q13".getBytes()), certClient.getKey()); //Error. Warning
                //c = RSA.encrypt(Utils.concatArrays(keyData, cert.getId().getBytes()), RSA.generateKeyPair().getPublic());
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] sign = new byte[0];
            try {
                sign = Digest.signData(Utils.concatArrays(r, c, certClient.getId().getBytes()), keyPairDig.getPrivate()); //Подписываем
            } catch (Exception e) {
                e.printStackTrace();
            }


            return new AKE1Response(c, sign, cert);
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
