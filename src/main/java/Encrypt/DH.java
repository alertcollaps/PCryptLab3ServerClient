package Encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import java.security.*;

public class DH {
    public static KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        return keyPairGenerator.generateKeyPair();
    }
    public static byte[] doDH(PrivateKey prKey, PublicKey pbKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH", "BC");
        ka.init(prKey);
        ka.doPhase(pbKey, true);
        return ka.generateSecret();
    }
}
