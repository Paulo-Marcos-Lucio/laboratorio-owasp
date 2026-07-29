package br.com.paulomarcos.labowasp.a04crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class HashSenhaTest {

    /** 72 bytes: exatamente o limite que o BCrypt consegue considerar. */
    private static final String PREFIXO_72_BYTES = "A".repeat(72);

    @Test
    void md5EhDeterministicoESemSal() {
        // MD5("123456") é público e consta em qualquer rainbow table.
        assertThat(HashSenha.md5("123456")).isEqualTo("e10adc3949ba59abbe56e057f20f883e");
        // sem sal: a mesma senha sempre gera o mesmo hash.
        assertThat(HashSenha.md5("123456")).isEqualTo(HashSenha.md5("123456"));
    }

    @Test
    void bcryptEhSalgadoEVerificavel() {
        String h1 = HashSenha.bcrypt("123456");
        String h2 = HashSenha.bcrypt("123456");

        assertThat(h1).isNotEqualTo(h2); // sal por senha => hashes diferentes
        assertThat(h1).startsWith("$2"); // formato bcrypt
        assertThat(HashSenha.bcryptConfere("123456", h1)).isTrue();
        assertThat(HashSenha.bcryptConfere("senha-errada", h1)).isFalse();
    }

    /**
     * Portão da CVE-2025-22228. Com spring-security-crypto até 6.3.7 / 6.4.3 este teste FALHA: o
     * {@code encode} aceitava a senha longa em silêncio (truncando em 72 bytes) e o {@code matches}
     * depois autenticava <b>qualquer</b> senha errada que compartilhasse os 72 primeiros bytes.
     * Numa versão corrigida o encoder recusa a senha longa.
     */
    @Test
    void bcryptRecusaSenhaAcimaDoLimiteDe72Bytes() {
        String passphraseLonga = PREFIXO_72_BYTES + "senha-real-do-usuario";

        assertThatThrownBy(() -> HashSenha.bcrypt(passphraseLonga))
                .as(
                        "encoder vulneravel a CVE-2025-22228 trunca em silencio em vez de"
                                + " recusar — e depois autentica senha errada")
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("72");
    }

    /**
     * Documenta um limite que continua existindo, para o material não prometer o que a biblioteca
     * não faz: o BCrypt só considera os 72 primeiros bytes. O {@code encode} passou a recusar
     * senhas maiores (teste acima), mas o {@code matches} de um hash legado de 72 bytes ainda
     * aceita uma senha mais longa com o mesmo prefixo. Por isso, em produção, senha longa exige
     * pré-hash (ex.: SHA-256 antes do BCrypt) ou um KDF sem esse limite (Argon2id, scrypt).
     */
    @Test
    void bcryptSoConsideraOs72PrimeirosBytes() {
        String hashDe72Bytes = HashSenha.bcrypt(PREFIXO_72_BYTES);

        assertThat(HashSenha.bcryptConfere(PREFIXO_72_BYTES + "-sufixo-ignorado", hashDe72Bytes))
                .as("limite conhecido do BCrypt: o sufixo acima de 72 bytes nao e comparado")
                .isTrue();
    }
}
