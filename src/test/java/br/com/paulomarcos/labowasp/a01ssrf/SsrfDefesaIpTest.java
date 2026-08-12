package br.com.paulomarcos.labowasp.a01ssrf;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Prova a defesa em profundidade (camada 2). Aqui a allowlist inclui de propósito hosts que
 * resolvem para endereços internos — isto é, a camada 1 (allowlist) os deixaria passar. O teste
 * mostra que a checagem de endereço interno os barra mesmo assim, sem nenhuma requisição de rede (o
 * bloqueio ocorre antes do fetch).
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "ssrf.allowlist=127.0.0.1,169.254.169.254,10.0.0.5")
class SsrfDefesaIpTest {

    /**
     * Assertar o MOTIVO, e não só o status, é o que impede o falso-verde: sem isso, uma requisição
     * barrada por qualquer outra guarda (ou por NXDOMAIN do DNS do runner) deixaria o teste passar
     * com a camada 2 apagada.
     */
    private static final String MOTIVO = "destino interno bloqueado";

    @Autowired private MockMvc mvc;

    @Test
    void corrigidoBloqueiaLoopbackAindaQueNaAllowlist() throws Exception {
        mvc.perform(get("/a01/ssrf/corrigido").param("url", "http://127.0.0.1:9/x"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(MOTIVO));
    }

    @Test
    void corrigidoBloqueiaIpDeMetadadosDeNuvemAindaQueNaAllowlist() throws Exception {
        // 169.254.169.254 é o endpoint de metadados de AWS/GCP/Azure — link-local.
        mvc.perform(
                        get("/a01/ssrf/corrigido")
                                .param("url", "http://169.254.169.254/latest/meta-data/"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(MOTIVO));
    }

    @Test
    void corrigidoBloqueiaIpPrivadoAindaQueNaAllowlist() throws Exception {
        mvc.perform(get("/a01/ssrf/corrigido").param("url", "http://10.0.0.5/admin"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(MOTIVO));
    }
}
