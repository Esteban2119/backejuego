package taxationland.security.keys;

import java.util.Base64;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class KeyGenerator {
    public static void main(String[] args) {
        String secret = Base64.getEncoder().encodeToString(
            Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded());
        System.out.println("Clave segura: " + secret);
    }
}
