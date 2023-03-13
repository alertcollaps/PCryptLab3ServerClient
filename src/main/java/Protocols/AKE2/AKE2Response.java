package Protocols.AKE2;

import Certifications.Cert;

public class AKE2Response {
    byte[] c;
    byte[] sig;
    Cert cert;
    AKE2Response(){

    }

    AKE2Response(byte[] c, byte[] sig, Cert cert){
        this.c = c;
        this.sig = sig;
        this.cert = cert;
    }
}
