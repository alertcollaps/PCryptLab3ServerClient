package Protocols.STS;

import Certifications.Cert;
import Encrypt.*;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;

public class STS {
    static int keySize = 32;
    static String preString = "[STS]:";
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
                logBuffer.append(preString + prePreString+ "Get Key is " + Utils.bytesToHex(key) + "\n");
            } else {
                logBuffer.append(preString + prePreString+ "Aborted" + "\n");
            }


        }
        public static boolean sendC2(byte[] v){
            Key symmetricKey = new SecretKeySpec(key, "AES"); //get key
            byte[] signUV = new byte[0];
            try {
                signUV = Digest.signData(Utils.concatArrays(keyPairDH.getPublic().getEncoded(), v), keyPairDigest.getPrivate());
                //signUV[0] += 10;//Error. Warning. Изменение на последнем этапе. Неправильная подпись
            } catch (Exception e) {
                e.printStackTrace();
            }
            byte[] encData = new byte[0];
            try {
                encData = AES.encrypt(symmetricKey.getEncoded(), signUV);
            } catch (Exception e) {
                e.printStackTrace();
            }
            STSResponse toServer = new STSResponse(null, encData, cert);
            logBuffer.append(preString + prePreString+ "Send to Server: " + "encData: " + Utils.bytesToHex(encData) + "\n" );
            return Server.sendCheck(toServer);
        }

        public static boolean SendCert(){

            logBuffer.append(preString + prePreString+ "Send to Server: " + "u: " + Utils.bytesToHex(keyPairDH.getPublic().getEncoded()) + "\n" );

            STSResponse STSResponse = Server.getU(keyPairDH.getPublic());
            if (STSResponse == null){
                return false;
            }
            logBuffer.append(preString + prePreString+ "Get from Server: c - " + Utils.bytesToHex(STSResponse.c) + ", \\\nCert - {id}:"
                    + STSResponse.cert.getId() + "\t {pub key}" + Utils.bytesToHex(STSResponse.cert.getKey().getEncoded()) + "\\\n" +
                    "v: " + Utils.bytesToHex(STSResponse.v.getEncoded()) + "\n");
            if (!checkAnswer(STSResponse)){
                return false;
            }



            return sendC2(STSResponse.v.getEncoded());
        }

        public static boolean checkAnswer(STSResponse STSResponse){
            String idQ = STSResponse.cert.getId();
            byte[] keyData = new byte[0];
            try {
                keyData = DH.doDH(keyPairDH.getPrivate(), STSResponse.v);
            } catch (Exception e) {
                e.printStackTrace();
            }
            key = HKDF.getKey(keyData);
            Key symmetricKey = new SecretKeySpec(key, "AES"); //get key

            byte[] decryptedSign = new byte[0];
            try {
                decryptedSign = AES.decrypt(symmetricKey.getEncoded(), STSResponse.c);
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                if (!Digest.checkSign(decryptedSign, Utils.concatArrays(keyPairDH.getPublic().getEncoded(), STSResponse.v.getEncoded()), STSResponse.cert.getKey())){
                    logBuffer.append(preString + prePreString+ "Failed check Sign" + "\n");
                    return false;
                }
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
        static PublicKey uClient;

        static {
            try {
                keyPairDH = DH.generateKeyPair();
                keyPairDigest = Digest.generateKeyPair();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static Cert cert = new Cert("002", keyPairDigest.getPublic());

        public static boolean sendCheck(STSResponse stsResponse){
            Key symmetricKey = new SecretKeySpec(key, "AES"); //get key
            byte[] decryptedSign = new byte[0];
            try {
                decryptedSign = AES.decrypt(symmetricKey.getEncoded(), stsResponse.c);
            } catch (Exception e) {
                e.printStackTrace();
            }
            boolean check = false;
            try {
                check = Digest.checkSign(decryptedSign, Utils.concatArrays(uClient.getEncoded(), keyPairDH.getPublic().getEncoded()), stsResponse.cert.getKey());
            } catch (Exception e) {
                e.printStackTrace();
            }
            String s = check ? ":Success!" : ":Aborted...";
            logBuffer.append(preString + prePreString+ "Checking final Client: " + check + s + "\n");
            return check;
        }


        public static STSResponse getU(PublicKey u){
            logBuffer.append(preString + prePreString+ "Get from Client: u - " + Utils.bytesToHex(u.getEncoded()) + "\n");


            byte[] keyData;
            try {
                keyData = DH.doDH(keyPairDH.getPrivate(), u); //key evaluate
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
            key = HKDF.getKey(keyData);
            logBuffer.append(preString + prePreString+ "Evaluate DH key: " + Utils.bytesToHex(keyData) + "\n");

            logBuffer.append(preString + prePreString+ "Evaluate HKDF key: " + Utils.bytesToHex(key) + "\n");
            Key symmetricKey = new SecretKeySpec(key, "AES"); //get key

            byte[] signUV = new byte[0];
            try {
                signUV = Digest.signData(Utils.concatArrays(u.getEncoded(), keyPairDH.getPublic().getEncoded()), keyPairDigest.getPrivate());
            } catch (Exception e) {
                e.printStackTrace();
            }

            byte[] c = new byte[0];
            try {
                c = AES.encrypt(symmetricKey.getEncoded(), signUV);
            } catch (Exception e) {
                e.printStackTrace();
            }
            PublicKey v = null;
            try {
                v = keyPairDH.getPublic(); //Открытый ключ DH

            } catch (Exception e) {
                e.printStackTrace();
            }
            uClient = u;
            return new STSResponse(v, c, cert);
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
