package br.com.paulomarcos.labowasp.a02crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * A02:2021 Cryptographic Failures — armazenamento de senha (CWE-916).
 *
 * <p>{@link #md5} representa o erro comum: hash rápido e sem sal. Senhas iguais
 * geram o mesmo hash (vulnerável a rainbow tables) e bilhões podem ser testados
 * por segundo. {@link #bcrypt} usa um algoritmo lento, com sal por senha e fator
 * de custo — o padrão correto.
 */
public final class HashSenha {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    private HashSenha() {}

    public static String md5(String senha) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(senha.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {  // MD5 sempre existe na JVM
            throw new IllegalStateException(e);
        }
    }

    public static String bcrypt(String senha) {
        return ENCODER.encode(senha);
    }

    public static boolean bcryptConfere(String senha, String hash) {
        return ENCODER.matches(senha, hash);
    }
}
