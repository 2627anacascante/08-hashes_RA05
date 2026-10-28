import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public String getSHA512AmbSalt(String pw, String salt)

public String getPBKDF2AmbSalt(String pw, String salt)

public String forcaBruta(String alg, String hash, String salt)

public String getInterval(long t1, long t2)

public static void main(String[] args) throws Exception {
    String salt = "qpoweiruañsIkdfjz";
    String pw = "aaabF!";

    Hashes h = new Hashes();

    String[] aHashes = {
        h.getSHA512AmbSalt(pw, salt),
        h.getPBKDF2AmbSalt(pw, salt)
    };

    String pwTrobat = null;
    String[] algorismes = {"SHA-512", "PBKDF2"};

    for (int i = 0; i < aHashes.length; i++) {
        System.out.printf("========================\n");
        System.out.printf("Algorisme: %s\n", algorismes[i]);
        System.out.printf("Hash: %s\n", aHashes[i]);
        System.out.printf("------------------------\n");
        System.out.printf("-- Inici de força bruta --\n");

        long t1 = System.currentTimeMillis();
        pwTrobat = h.forcaBruta(algorismes[i], aHashes[i], salt);
        long t2 = System.currentTimeMillis();

        System.out.printf("Pass: %s\n", pwTrobat);
        System.out.printf("Provats: %d\n", h.npass);
        System.out.printf("Temps : %s\n", h.getInterval(t1, t2));
        System.out.printf("------------------------\n\n");
    }
}