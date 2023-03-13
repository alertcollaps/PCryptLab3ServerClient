import Encrypt.DH;
import Encrypt.HKDF;
import Encrypt.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

public class main {
    public static void main(String[] args) {
        try {
            KeyPair pair1 = DH.generateKeyPair();
            KeyPair pair2 = DH.generateKeyPair();
            byte[] secret1 = DH.doDH(pair1.getPrivate(), pair2.getPublic());
            byte[] secret2 = DH.doDH(pair2.getPrivate(), pair1.getPublic());


            byte[] secretHKDF1 = HKDF.getKey(secret1);
            byte[] secretHKDF2 = HKDF.getKey(secret2);

            KeyPair pair11 = RSA.generateKeyPair();
            KeyPair pair22 = RSA.generateKeyPair();
            byte[] hel = RSA.encrypt("hello".getBytes(StandardCharsets.UTF_8), pair11.getPublic());
            byte[] dehel = RSA.decrypt(hel, pair11.getPrivate());
            System.out.println(new String(dehel));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

