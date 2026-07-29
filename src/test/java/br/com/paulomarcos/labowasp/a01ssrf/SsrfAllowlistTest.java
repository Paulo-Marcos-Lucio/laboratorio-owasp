package br.com.paulomarcos.labowasp.a01ssrf;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Lado positivo (sem falso positivo): uma URL de host permitido que resolve para um endereço
 * público passa nas duas camadas e o conteúdo é devolvido. O host é o literal 203.0.113.10
 * (TEST-NET-3, RFC 5737, público e não roteável) — {@code getAllByName} o interpreta sem DNS. O
 * {@link HttpBuscador} é mockado para não depender da rede: o que se prova aqui é a <b>decisão</b>
 * (permitir e buscar), não a conectividade.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "ssrf.allowlist=203.0.113.10")
class SsrfAllowlistTest {

    @Autowired private MockMvc mvc;

    @MockBean private HttpBuscador buscador;

    @Test
    void corrigidoPermiteHostDaAllowlistComEnderecoPublico() throws Exception {
        when(buscador.buscar(any())).thenReturn("CONTEUDO-PUBLICO-OK");

        mvc.perform(get("/a01/ssrf/corrigido").param("url", "http://203.0.113.10/dados"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("CONTEUDO-PUBLICO-OK")));
    }
}
