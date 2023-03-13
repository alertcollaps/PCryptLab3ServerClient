package Protocols.STS;

import Certifications.Cert;

import java.security.PublicKey;

public class STSResponse {
    PublicKey v;
    byte[] c;
    Cert cert;
    STSResponse(){

    }

    STSResponse(PublicKey v, byte[] c, Cert cert){
        this.v = v;
        this.c = c;
        this.cert = cert;
    }
}
