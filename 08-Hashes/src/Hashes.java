import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.HexFormat;

public class Hashes{

public String getSHA512AmbSalt(String pw, String salt)throws NoSuchAlgorithmException{
// byte[] bytes = { 10, 31, -1 };
// String texto = HexFormat.of().formatHex(bytes);
byte[] bytessha512 = MessageDigest
//MessageDigest es una clase de Java para calcular resúmenes criptográficos (hashes) de datos, como una contraseña. Por ejemplo, puede calcular un SHA-512.
            .getInstance("SHA-512")
            .digest((pw + salt)//une pw y salt
            .getBytes(StandardCharsets.UTF_8));//metodo que necesita los bytes
    
return HexFormat.of().formatHex(bytessha512);    
//convierte bytes a texto hexadecimal- crea formateador hexadecimal
}

public String getPBKDF2AmbSalt(String pw, String salt){

    byte[] bytespbkdf2 = MessageDigest.getInstance("PBKDF2").digest((pw+salt).getBytes(StandardCharsets.UTF_8));

return HexFormat.of().formatHex(bytespbkdf2);
}

public String forcaBruta(String alg, String hash, String salt){
    public char[] charset = "abcdefABCDEF1234567890".toCharArray();
return;
}

public String getInterval(long t1, long t2){}return;

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
}