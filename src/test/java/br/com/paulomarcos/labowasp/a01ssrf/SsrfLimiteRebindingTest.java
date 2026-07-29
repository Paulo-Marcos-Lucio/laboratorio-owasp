package br.com.paulomarcos.labowasp.a01ssrf;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Este teste NÃO prova que a correção funciona: ele documenta um <b>limite</b> dela.
 *
 * <p>O {@code /corrigido} valida o host, resolve o endereço e recusa endereço interno. Mas a
 * validação e a busca resolvem o nome de forma independente: o {@code InetAddress[]} já validado é
 * descartado e o cliente HTTP resolve o host da URI de novo. É um check-then-use (TOCTOU). Com um
 * DNS que troca a resposta entre as duas consultas — DNS rebinding —, a camada 2 aprova um IP
 * público e a conexão sai para o loopback.
 *
 * <p>Montagem: {@link ResolvedorDeRebinding} devolve 203.0.113.10 na 1ª consulta de {@code
 * rebind.exemplo.com} e 127.0.0.1 depois; um {@link HttpServer} de loopback guarda o segredo; a
 * allowlist contém o host. O cache de DNS da JVM está desligado no {@code pom.xml} ({@code
 * -Dsun.net.inetaddr.ttl=0}) para o rebinding caber numa única requisição — num alvo real o
 * atacante simplesmente espera o TTL expirar.
 *
 * <p>Se um dia este teste passar a falhar porque a resposta virou 400, ótimo: quer dizer que a
 * mitigação de verdade (conectar no endereço já validado, ou sair por um proxy de egresso) foi
 * implementada. Aí este teste deve ser reescrito, não apagado.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "ssrf.allowlist=" + ResolvedorDeRebinding.HOST)
class SsrfLimiteRebindingTest {

    private static final String SEGREDO = "SEGREDO-INTERNO-REBIND";

    private static HttpServer servicoInterno;
    private static int porta;

    @Autowired private MockMvc mvc;

    @BeforeAll
    static void subirServicoInterno() throws IOException {
        servicoInterno =
                HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        servicoInterno.createContext(
                "/interno",
                troca -> {
                    byte[] corpo = SEGREDO.getBytes(StandardCharsets.UTF_8);
                    troca.sendResponseHeaders(200, corpo.length);
                    try (OutputStream saida = troca.getResponseBody()) {
                        saida.write(corpo);
                    }
                });
        servicoInterno.start();
        porta = servicoInterno.getAddress().getPort();
    }

    @AfterAll
    static void derrubarServicoInterno() {
        servicoInterno.stop(0);
    }

    @Test
    void corrigidoNaoImpedeDnsRebinding() throws Exception {
        String url = "http://" + ResolvedorDeRebinding.HOST + ":" + porta + "/interno";

        mvc.perform(get("/a01/ssrf/corrigido").param("url", url))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SEGREDO)));

        Assertions.assertThat(ResolvedorDeRebinding.consultas())
                .as("o host precisa ser resolvido ao menos duas vezes — e esse e o defeito")
                .isGreaterThanOrEqualTo(2);
    }
}
