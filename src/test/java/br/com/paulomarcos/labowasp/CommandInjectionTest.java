package br.com.paulomarcos.labowasp;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class CommandInjectionTest {

    // "&&" encadeia comandos tanto no /bin/sh quanto no cmd.exe: o echo injetado roda de fato.
    private static final String PAYLOAD = "127.0.0.1 && echo INJETADO";

    @Autowired
    private MockMvc mvc;

    @Test
    void vulneravelExecutaComandoInjetado() throws Exception {
        // Prova real: o shell roda um SEGUNDO comando. A saída traz "INJETADO" numa linha
        // própria — não o literal "echo INJETADO" —, ou seja, o comando foi executado.
        mvc.perform(get("/a03/cmd/vulneravel").param("host", PAYLOAD))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("INJETADO")))
                .andExpect(content().string(not(containsString("echo INJETADO"))));
    }

    @Test
    void corrigidoBloqueiaComandoInjetado() throws Exception {
        mvc.perform(get("/a03/cmd/corrigido").param("host", PAYLOAD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("INJETADO"))));
    }

    @Test
    void corrigidoBloqueiaPontoEVirgula() throws Exception {
        mvc.perform(get("/a03/cmd/corrigido").param("host", "x; whoami"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void corrigidoBloqueiaSubstituicaoDeComando() throws Exception {
        // $(...) e crases são vetores clássicos de injeção via shell.
        mvc.perform(get("/a03/cmd/corrigido").param("host", "$(whoami)"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void corrigidoPermiteHostLegitimo() throws Exception {
        // Sem falso positivo: um hostname legítimo continua aceito.
        mvc.perform(get("/a03/cmd/corrigido").param("host", "servidor-01.local"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("servidor-01.local")));
    }
}
