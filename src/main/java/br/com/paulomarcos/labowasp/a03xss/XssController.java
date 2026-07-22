package br.com.paulomarcos.labowasp.a03xss;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/**
 * A03:2021 Injection — Cross-Site Scripting refletido (CWE-79).
 *
 * <p>O {@code /vulneravel} devolve a entrada dentro do HTML sem codificar: um
 * {@code <script>} enviado pelo usuário executa no navegador da vítima. O
 * {@code /corrigido} aplica codificação de entidades HTML na saída.
 */
@RestController
@RequestMapping("/a03/xss")
public class XssController {

    @GetMapping(value = "/vulneravel", produces = MediaType.TEXT_HTML_VALUE)
    public String vulneravel(@RequestParam String q) {
        // A entrada é refletida crua no HTML — o navegador executa qualquer <script>.
        return "<p>Voce buscou: " + q + "</p>";
    }

    @GetMapping(value = "/corrigido", produces = MediaType.TEXT_HTML_VALUE)
    public String corrigido(@RequestParam String q) {
        // Codificacao de saida: < vira &lt;, quebrando a injecao de script.
        return "<p>Voce buscou: " + HtmlUtils.htmlEscape(q) + "</p>";
    }
}
