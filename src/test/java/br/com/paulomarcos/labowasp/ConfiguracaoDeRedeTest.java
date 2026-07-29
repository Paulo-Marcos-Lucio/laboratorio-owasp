package br.com.paulomarcos.labowasp;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * Portão de configuração: o laboratório só pode escutar no loopback.
 *
 * <p>O endpoint {@code /a05/cmd/vulneravel} entrega a entrada do usuário a um shell do sistema
 * operacional. Com o padrão do Spring Boot ({@code 0.0.0.0}), isso é execução de comando
 * arbitrária, sem autenticação, alcançável por qualquer máquina da mesma rede. Este teste reprova o
 * build se {@code server.address} sumir ou deixar de ser o loopback — é a única proteção contra a
 * regressão silenciosa de uma linha de propriedade.
 */
class ConfiguracaoDeRedeTest {

    @Test
    void aplicacaoEscutaSomenteNoLoopback() throws Exception {
        Properties propriedades = new Properties();
        try (InputStream entrada =
                ConfiguracaoDeRedeTest.class.getResourceAsStream("/application.properties")) {
            assertThat(entrada).as("application.properties no classpath").isNotNull();
            propriedades.load(entrada);
        }

        assertThat(propriedades.getProperty("server.address"))
                .as(
                        "server.address precisa confinar o laboratorio ao loopback:"
                                + " sem ele o Spring Boot escuta em 0.0.0.0 e expoe RCE nao"
                                + " autenticada para a rede inteira")
                .isEqualTo("127.0.0.1");
    }
}
