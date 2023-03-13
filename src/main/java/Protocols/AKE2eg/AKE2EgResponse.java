package Protocols.AKE2eg;

import Certifications.Cert;

import java.security.PublicKey;

public class AKE2EgResponse {
    PublicKey c;
    byte[] sig;
    Cert cert;
    AKE2EgResponse(){

    }

    AKE2EgResponse(PublicKey c, byte[] sig, Cert cert){
        this.c = c;
        this.sig = sig;
        this.cert = cert;
    }
}
