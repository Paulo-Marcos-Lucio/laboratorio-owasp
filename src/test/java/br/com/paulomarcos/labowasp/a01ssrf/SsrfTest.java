package br.com.paulomarcos.labowasp.a01ssrf;

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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Prova o SSRF de verdade, sem tocar a internet: sobe um servidor HTTP de loopback que representa
 * um "serviço interno" e devolve um segredo. O lado vulnerável o alcança (vazando o segredo); o
 * corrigido o barra.
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
        mvc.perform(get("/a01/ssrf/vulneravel").param("url", urlInterna))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(SEGREDO)));
    }

    @Test
    void corrigidoBloqueiaServicoInternoDeLoopback() throws Exception {
        // Mesma URL, endpoint corrigido: bloqueado (host fora da allowlist) e o segredo
        // nunca aparece na resposta.
        mvc.perform(get("/a01/ssrf/corrigido").param("url", urlInterna))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("host fora da allowlist"))
                .andExpect(content().string(not(containsString(SEGREDO))));
    }

    @Test
    void corrigidoBloqueiaHostForaDaAllowlist() throws Exception {
        // O host é o literal 203.0.113.10 (TEST-NET-3, RFC 5737): getAllByName o interpreta
        // sem consultar DNS e ele é público. Assim o ÚNICO caminho possível para o 400 é a
        // allowlist. Com um host inventado (evil.example) quem devolvia 400 era o NXDOMAIN
        // do DNS do runner — e apagar a allowlist inteira deixava o teste verde.
        mvc.perform(get("/a01/ssrf/corrigido").param("url", "http://203.0.113.10/coleta"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("host fora da allowlist"));
    }

    @Test
    void corrigidoBloqueiaEsquemaNaoHttp() throws Exception {
        // file: é vetor clássico de SSRF para ler arquivos locais do servidor. O host está
        // DENTRO da allowlist padrão de propósito: se o guard de esquema for removido, a
        // requisição não cai em nenhuma outra guarda e o teste fica vermelho.
        mvc.perform(get("/a01/ssrf/corrigido").param("url", "file://api.example.com/etc/passwd"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("esquema nao permitido"));
    }

    @Test
    void vulneravelResponde502ENao500QuandoODestinoNaoResponde() throws Exception {
        // A porta 9 (discard) não tem nada escutando: conexão recusada na hora. O endpoint
        // continua vulnerável, mas um destino inalcançável — 169.254.169.254 fora de uma
        // nuvem, o exemplo do README — devolve o motivo em vez de "Internal Server Error".
        mvc.perform(get("/a01/ssrf/vulneravel").param("url", "http://127.0.0.1:9/x"))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(containsString("nao foi possivel buscar a URL")));
    }

    @Test
    void corrigidoBloqueiaUrlSemHost() throws Exception {
        // Caso separado: aqui não há host nenhum, então quem barra é a guarda "host ausente"
        // — e não o guard de esquema (que já barraria antes).
        mvc.perform(get("/a01/ssrf/corrigido").param("url", "file:///etc/passwd"))
                .andExpect(status().isBadRequest());
    }
}
