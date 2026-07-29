package br.com.paulomarcos.labowasp.a01ssrf;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.stereotype.Component;

/**
 * Faz uma requisição HTTP GET e devolve o corpo como texto.
 *
 * <p>Componente único usado tanto pelo endpoint vulnerável quanto pelo corrigido: a diferença de
 * segurança está em <b>o que</b> se deixa buscar (a validação no controlador), não no mecanismo de
 * busca. Não segue redirecionamentos ({@code Redirect.NEVER}) — um redirect poderia levar um host
 * permitido a apontar para a rede interna — e usa timeouts curtos para o laboratório nunca travar.
 */
@Component
public class HttpBuscador {

    /** Corta o corpo para o laboratório não devolver respostas gigantes. */
    private static final int LIMITE_CORPO = 8192;

    private final HttpClient cliente =
            HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

    public String buscar(URI uri) throws IOException, InterruptedException {
        HttpRequest requisicao =
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build();
        HttpResponse<String> resposta =
                cliente.send(
                        requisicao, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        String corpo = resposta.body();
        return corpo.length() > LIMITE_CORPO ? corpo.substring(0, LIMITE_CORPO) : corpo;
    }
}
