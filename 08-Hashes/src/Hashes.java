import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Hashes {

    public static final char[] SET = "abcdefABCDEF1234567890!".toCharArray();

    public int npass = 0;

    // ---------- SHA-512 con salt ----------
    public String getSHA512AmbSalt(String pw, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt.getBytes(StandardCharsets.UTF_8));   
        byte[] bytes = md.digest(pw.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(bytes);
    }

    // ---------- PBKDF2 con salt ----------
    public String getPBKDF2AmbSalt(String pw, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;   
        int keyLength = 256;      
        PBEKeySpec spec = new PBEKeySpec(
                pw.toCharArray(),
                salt.getBytes(StandardCharsets.UTF_8),
                iterations,
                keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] bytes = skf.generateSecret(spec).getEncoded();
        return HexFormat.of().formatHex(bytes);
    }

    // ---------- Fuerza bruta real ----------
    public String forcaBruta(String alg, String hashObjectiu, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        npass = 0;

        for (int longitud = 1; longitud <= 6; longitud++) {
            char[] buffer = new char[longitud];
            String trobat = backtracking(alg, hashObjectiu, salt, buffer, 0);
            if (trobat != null) return trobat;
        }
        return null;
    }

    private String backtracking(String alg, String hashObjectiu, String salt,
                                char[] buffer, int pos)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        if (pos == buffer.length) {
            String candidat = new String(buffer);
            npass++;
            String hashCandidat = calculaHash(alg, candidat, salt);
            if (hashCandidat.equalsIgnoreCase(hashObjectiu)) {
                return candidat;
            }
            return null;
        }

        for (char c : SET) {
            buffer[pos] = c;
            String res = backtracking(alg, hashObjectiu, salt, buffer, pos + 1);
            if (res != null) return res;
        }
        return null;
    }

    private String calculaHash(String alg, String pw, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        if ("SHA-512".equals(alg)) {
            return getSHA512AmbSalt(pw, salt);
        } else if ("PBKDF2".equals(alg)) {
            return getPBKDF2AmbSalt(pw, salt);
        }
        throw new IllegalArgumentException("Algorisme no suportat: " + alg);
    }

    // ---------- Formato del tiempo ----------
    public String getInterval(long t1, long t2) {
        long totalSegons = (t2 - t1) / 1000;
        long dies   = totalSegons / 86400;
        long hores  = (totalSegons % 86400) / 3600;
        long minuts = (totalSegons % 3600) / 60;
        long segons = totalSegons % 60;
        return dies + " Dies / " + hores + " Hores / "
             + minuts + " Minuts / " + segons + " Segons";
    }

    // ---------- main ----------
    public static void main(String[] args) throws Exception {
        String salt = "qpoweiruañsIkdfjz";
        String pw   = "aaabF!";    // contraseña a "romper"

        Hashes h = new Hashes();

        String[] aHashes = {
            h.getSHA512AmbSalt(pw, salt),
            h.getPBKDF2AmbSalt(pw, salt)
        };

        String[] algorismes = { "SHA-512", "PBKDF2" };

        for (int i = 0; i < aHashes.length; i++) {
            System.out.println("========================");
            System.out.printf("Algorisme: %s%n", algorismes[i]);
            System.out.printf("Hash: %s%n", aHashes[i]);
            System.out.println("------------------------");
            System.out.println("-- Inici de força bruta --");

            long t1 = System.currentTimeMillis();
            String pwTrobat = h.forcaBruta(algorismes[i], aHashes[i], salt);
            long t2 = System.currentTimeMillis();

            System.out.printf("Pass: %s%n", pwTrobat);
            System.out.printf("Provats: %d%n", h.npass);
            System.out.printf("Temps : %s%n", h.getInterval(t1, t2));
            System.out.println("------------------------\n");
        }
    }
}