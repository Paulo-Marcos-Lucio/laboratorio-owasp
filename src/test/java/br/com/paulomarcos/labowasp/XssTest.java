package br.com.paulomarcos.labowasp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class XssTest {

    private static final String PAYLOAD = "<script>alert(1)</script>";

    @Autowired
    private MockMvc mvc;

    @Test
    void vulneravelRefleteScriptCru() throws Exception {
        String body = mvc.perform(get("/a03/xss/vulneravel").param("q", PAYLOAD))
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(body).contains("<script>");
    }

    @Test
    void corrigidoEscapaOHtml() throws Exception {
        String body = mvc.perform(get("/a03/xss/corrigido").param("q", PAYLOAD))
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(body).doesNotContain("<script>");
        assertThat(body).contains("&lt;script&gt;");
    }
}
