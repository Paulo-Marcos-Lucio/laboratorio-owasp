package br.com.paulomarcos.labowasp;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class OpenRedirectTest {

    private static final String DESTINO_EXTERNO = "https://site-falso.example";

    @Autowired
    private MockMvc mvc;

    @Test
    void vulneravelRedirecionaParaDominioExterno() throws Exception {
        // O exploit: a vítima é levada para fora do domínio, base de phishing.
        mvc.perform(get("/a01/redirect/vulneravel").param("destino", DESTINO_EXTERNO))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(DESTINO_EXTERNO));
    }

    @Test
    void corrigidoBloqueiaDominioExterno() throws Exception {
        mvc.perform(get("/a01/redirect/corrigido").param("destino", DESTINO_EXTERNO))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void corrigidoBloqueiaUrlProtocoloRelativa() throws Exception {
        // "//host" nao tem esquema mas o navegador o trata como https://host.
        mvc.perform(get("/a01/redirect/corrigido").param("destino", "//site-falso.example"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void corrigidoBloqueiaTruqueDeBarraInvertida() throws Exception {
        // "/\host" — a barra invertida vira barra em muitos navegadores, virando externa.
        mvc.perform(get("/a01/redirect/corrigido").param("destino", "/\\site-falso.example"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void corrigidoPermiteCaminhoRelativoLegitimo() throws Exception {
        // O caso de uso legítimo continua funcionando: redirect interno.
        mvc.perform(get("/a01/redirect/corrigido").param("destino", "/painel"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/painel"));
    }
}
