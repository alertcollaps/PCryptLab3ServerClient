package Protocols.AKE1;

import Certifications.Cert;

public class AKE1Response {
    byte[] c;
    byte[] sig;
    Cert cert;
    AKE1Response(){

    }

    AKE1Response(byte[] c, byte[] sig, Cert cert){
        this.c = c;
        this.sig = sig;
        this.cert = cert;
    }
}
