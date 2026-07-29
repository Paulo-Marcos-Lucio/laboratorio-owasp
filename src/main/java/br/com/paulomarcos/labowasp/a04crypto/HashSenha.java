package br.com.paulomarcos.labowasp.a04crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * A04:2025 Cryptographic Failures — armazenamento de senha (CWE-916).
 *
 * <p>{@link #md5} representa o erro comum: hash rápido e sem sal. Senhas iguais geram o mesmo hash
 * (vulnerável a rainbow tables) e bilhões podem ser testados por segundo. {@link #bcrypt} usa um
 * algoritmo lento, com sal por senha e fator de custo — o padrão correto.
 *
 * <p><b>Limite do BCrypt: 72 bytes.</b> O algoritmo só considera os 72 primeiros bytes da senha — o
 * resto é ignorado. Duas consequências, ambas cobertas por teste:
 *
 * <ul>
 *   <li>{@link #bcrypt} <b>lança</b> {@link IllegalArgumentException} para senha maior que isso.
 *       Versões de spring-security-crypto até 6.3.7 / 6.4.3 truncavam em silêncio, e o {@link
 *       #bcryptConfere} então autenticava qualquer senha errada que compartilhasse os 72 primeiros
 *       bytes (CVE-2025-22228). Este laboratório exige uma versão corrigida.
 *   <li>{@link #bcryptConfere} continua comparando só os 72 primeiros bytes de um hash já
 *       existente. Para aceitar passphrases longas em produção, faça pré-hash (SHA-256 e
 *       codificação antes do BCrypt) ou use um KDF sem esse limite (Argon2id, scrypt).
 * </ul>
 */
public final class HashSenha {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    private HashSenha() {}

    public static String md5(String senha) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(senha.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) { // MD5 sempre existe na JVM
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
