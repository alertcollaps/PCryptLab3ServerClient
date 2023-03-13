package Certifications;

import java.security.Key;

public class Cert {
    private String id;
    private Key key;
    Cert(){

    }

    public Cert(String id, Key key){
        this.id = id;
        this.key = key;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
