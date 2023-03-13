package Protocols.AKE1eg;

import Certifications.Cert;

import java.security.PublicKey;

public class AKE1EgResponse {
    PublicKey c;
    byte[] sig;
    Cert cert;
    AKE1EgResponse(){

    }

    AKE1EgResponse(PublicKey c, byte[] sig, Cert cert){
        this.c = c;
        this.sig = sig;
        this.cert = cert;
    }
}
