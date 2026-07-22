package br.com.paulomarcos.labowasp;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class IdorTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void vulneravelVazaNotaDeOutroUsuario() throws Exception {
        // bob pede a nota 1, que é da alice — e recebe.
        mvc.perform(get("/a01/idor/vulneravel/1").header("X-Usuario", "bob"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dono").value("alice"));
    }

    @Test
    void corrigidoBloqueiaNotaDeOutroUsuario() throws Exception {
        mvc.perform(get("/a01/idor/corrigido/1").header("X-Usuario", "bob"))
                .andExpect(status().isForbidden());
    }

    @Test
    void corrigidoPermiteDono() throws Exception {
        mvc.perform(get("/a01/idor/corrigido/2").header("X-Usuario", "bob"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dono").value("bob"));
    }

    // Regressão: id inexistente devolvia 200 com corpo vazio (fail-silent). Agora é 404,
    // sem deixar de preservar o IDOR (nenhuma checagem de dono) no endpoint vulnerável.
    @Test
    void vulneravelIdInexistenteRetorna404() throws Exception {
        mvc.perform(get("/a01/idor/vulneravel/999").header("X-Usuario", "bob"))
                .andExpect(status().isNotFound());
    }
}
