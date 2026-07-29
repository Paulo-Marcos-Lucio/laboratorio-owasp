package br.com.paulomarcos.labowasp.a05sqli;

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
class SqlInjectionTest {

    @Autowired private MockMvc mvc;

    @Test
    void injecaoRetornaTabelaInteira() throws Exception {
        // O payload transforma o WHERE em sempre-verdadeiro e vaza os 3 produtos.
        mvc.perform(get("/a05/sqli/vulneravel").param("nome", "Notebook' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3));
    }

    @Test
    void consultaParametrizadaBloqueiaInjecao() throws Exception {
        mvc.perform(get("/a05/sqli/corrigido").param("nome", "Notebook' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void buscaLegitimaContinuaFuncionando() throws Exception {
        mvc.perform(get("/a05/sqli/corrigido").param("nome", "Notebook"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }
}
