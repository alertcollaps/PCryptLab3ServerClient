package Protocols.AKE2;


import Certifications.Cert;
import Encrypt.Digest;
import Encrypt.RSA;
import Encrypt.Utils;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class AKE2 {
    static int keySize = 32;
    static String preString = "[AKE2]:";
    public static class Client{
        static String prePreString = "Client:";
        static StringBuffer logBuffer = new StringBuffer();
        public static KeyPair keyPairDig;
        public static KeyPair keyPairRsa;
        static byte[] key = new byte[keySize];

        static {
            try {
                keyPairDig = Digest.generateKeyPair();
                keyPairRsa = RSA.generateKeyPair();
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
            byte[] signPk = new byte[0];
            try {
                signPk = Digest.signData(keyPairRsa.getPublic().getEncoded(), keyPairDig.getPrivate());
            } catch (Exception e) {
                e.printStackTrace();
            }
            //signPk[0] += 10; //Warning. Error меняем подпись на стороне клиента
            logBuffer.append(preString + prePreString+ "Send to Server: pk - " + Utils.bytesToHex(keyPairRsa.getPublic().getEncoded()) + "\\\nSign: " + Utils.bytesToHex(signPk) + ", \\\nCert - {id}:"
                    + cert.getId() + "\t {pub key}" + Utils.bytesToHex(cert.getKey().getEncoded()) + "\n");

            AKE2Response ake2Response = Server.getCert(keyPairRsa.getPublic(), signPk, cert);
            if (ake2Response == null){

                return false;
            }
            logBuffer.append(preString + prePreString+ "Get from Server: c - " + Utils.bytesToHex(ake2Response.c) + ", \\\nCert - {id}:"
                    + ake2Response.cert.getId() + "\t {pub key}" + Utils.bytesToHex(ake2Response.cert.getKey().getEncoded()) + "\\\n" +
                    "Sign: " + Utils.bytesToHex(ake2Response.sig) + "\n");

            return checkAnswer(ake2Response, keyPairRsa.getPublic().getEncoded());
        }

        public static boolean checkAnswer(AKE2Response ake1Response, byte[] pk){
            String idQ = ake1Response.cert.getId();
            try {
                if (!Digest.checkSign(ake1Response.sig, Utils.concatArrays(pk, ake1Response.c, cert.getId().getBytes()), ake1Response.cert.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return false;
                }
                byte[] decrMessage = RSA.decrypt(ake1Response.c, keyPairRsa.getPrivate());

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


        public static AKE2Response getCert(PublicKey pk, byte[] signPk, Cert certClient){
            logBuffer.append(preString + prePreString+ "Get from Client: pk - " + Utils.bytesToHex(pk.getEncoded()) + "\\\nSign: " + Utils.bytesToHex(signPk) + ", \\\nCert - {id}:"
                    + certClient.getId() + "\t {pub key}" + Utils.bytesToHex(certClient.getKey().getEncoded()) + "\n");
            try {
                if (!Digest.checkSign(signPk, pk.getEncoded(), certClient.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] keyData = Utils.generateBytes(keySize);
            logBuffer.append(preString + prePreString+ "Generate key: " + Utils.bytesToHex(keyData) + "\n");
            byte[] c = new byte[0];
            try {

                c = RSA.encrypt(Utils.concatArrays(keyData, cert.getId().getBytes()), pk);
                //c = RSA.encrypt(Utils.concatArrays(keyData, "q13".getBytes()), certClient.getKey()); //Error. Warning
                //c = RSA.encrypt(Utils.concatArrays(keyData, cert.getId().getBytes()), RSA.generateKeyPair().getPublic());
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] sign = new byte[0];
            try {
                sign = Digest.signData(Utils.concatArrays(pk.getEncoded(), c, certClient.getId().getBytes()), keyPairDig.getPrivate()); //Подписываем
            } catch (Exception e) {
                e.printStackTrace();
            }


            return new AKE2Response(c, sign, cert);
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
