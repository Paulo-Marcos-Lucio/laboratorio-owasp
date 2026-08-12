package br.com.paulomarcos.labowasp.a01redirect;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class OpenRedirectTest {

    private static final String DESTINO_EXTERNO = "https://site-falso.example";

    @Autowired private MockMvc mvc;

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

    @Test
    void corrigidoPermiteRaiz() throws Exception {
        // Falso positivo que existia: "/" (a raiz, o destino pós-login mais comum) tem
        // tamanho 1 e era recusado com 400 pela guarda "length() < 2".
        mvc.perform(get("/a01/redirect/corrigido").param("destino", "/"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void corrigidoRecusaDestinoMalformadoCom400ENao500() throws Exception {
        // Um espaço no caminho não é URI válido: o URI.create estourava
        // IllegalArgumentException para fora do controlador, virando 500 na versão
        // apresentada como "a correta". Entrada inválida do usuário é 400.
        mvc.perform(get("/a01/redirect/corrigido").param("destino", "/meu painel"))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void vulneravelRecusaDestinoMalformadoCom400ENao500() throws Exception {
        // O lado vulnerável continua vulnerável (ver o primeiro teste); o que ele deixa de
        // fazer é transformar entrada que nem é URI em erro do servidor.
        mvc.perform(get("/a01/redirect/vulneravel").param("destino", "http://["))
                .andExpect(status().isBadRequest());
    }
}
