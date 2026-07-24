package br.com.paulomarcos.labowasp;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Prova o SSRF de verdade, sem tocar a internet: sobe um servidor HTTP de loopback que
 * representa um "serviço interno" e devolve um segredo. O lado vulnerável o alcança
 * (vazando o segredo); o corrigido o barra.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SsrfTest {

    static final String SEGREDO = "SEGREDO-INTERNO-42";

    private static HttpServer servicoInterno;
    private static String urlInterna;

    @Autowired private MockMvc mvc;

    @BeforeAll
    static void subirServicoInterno() throws IOException {
        // Loopback, porta 0 = o SO escolhe uma livre. Isto simula um serviço acessível só
        // de dentro da rede do servidor — exatamente o que o SSRF explora.
        servicoInterno = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
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
        int porta = servicoInterno.getAddress().getPort();
        urlInterna = "http://127.0.0.1:" + porta + "/interno";
    }

    @AfterAll
    static void derrubarServicoInterno() {
        servicoInterno.stop(0);
    }

    @Test
    void vulneravelAlcancaServicoInternoEVazaSegredo() throws Exception {
        // Prova real: o servidor busca a URL de loopback escolhida pelo atacante e devolve
        // o segredo que só o serviço interno conhece. Isto é SSRF acontecendo.
        mvc.perform(get("/a10/ssrf/vulneravel").param("url", urlInterna))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SEGREDO)));
    }

    @Test
    void corrigidoBloqueiaServicoInternoDeLoopback() throws Exception {
        // Mesma URL, endpoint corrigido: bloqueado (host fora da allowlist) e o segredo
        // nunca aparece na resposta.
        mvc.perform(get("/a10/ssrf/corrigido").param("url", urlInterna))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString(SEGREDO))));
    }

    @Test
    void corrigidoBloqueiaHostForaDaAllowlist() throws Exception {
        mvc.perform(get("/a10/ssrf/corrigido").param("url", "https://evil.example/coleta"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void corrigidoBloqueiaEsquemaNaoHttp() throws Exception {
        // file: é vetor clássico de SSRF para ler arquivos locais do servidor.
        mvc.perform(get("/a10/ssrf/corrigido").param("url", "file:///etc/passwd"))
                .andExpect(status().isBadRequest());
    }
}
