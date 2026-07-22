package br.com.paulomarcos.labowasp;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.paulomarcos.labowasp.a02crypto.HashSenha;
import org.junit.jupiter.api.Test;

class HashSenhaTest {

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
}
