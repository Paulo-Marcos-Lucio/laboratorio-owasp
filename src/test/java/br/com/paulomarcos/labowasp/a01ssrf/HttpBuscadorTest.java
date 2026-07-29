package br.com.paulomarcos.labowasp.a01ssrf;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Os dois controles de segurança do {@link HttpBuscador} — {@code Redirect.NEVER} e o corte de
 * corpo — estavam afirmados no javadoc e não tinham teste nenhum: dava para trocar por {@code
 * Redirect.ALWAYS} e {@code Integer.MAX_VALUE} com a suíte inteira verde.
 *
 * <p>Aqui não há Spring nem internet: um {@link HttpServer} de loopback serve um "serviço interno"
 * com segredo, um endereço que responde 302 apontando para ele (o bypass de allowlist mais
 * explorado depois do rebinding) e um recurso de 20 KB.
 */
class HttpBuscadorTest {

    private static final String SEGREDO = "SEGREDO-INTERNO-REDIRECT";
    private static final int TAMANHO_GRANDE = 20_000;

    private static HttpServer servidor;
    private static String base;

    private final HttpBuscador buscador = new HttpBuscador();

    @BeforeAll
    static void subirServidor() throws IOException {
        servidor = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        int porta = servidor.getAddress().getPort();
        base = "http://127.0.0.1:" + porta;

        servidor.createContext("/interno", troca -> responder(troca, 200, SEGREDO));
        servidor.createContext(
                "/salto",
                troca -> {
                    troca.getResponseHeaders().add("Location", base + "/interno");
                    responder(troca, 302, "redirecionando");
                });
        servidor.createContext(
                "/grande", troca -> responder(troca, 200, "x".repeat(TAMANHO_GRANDE)));
        servidor.start();
    }

    private static void responder(
            com.sun.net.httpserver.HttpExchange troca, int status, String texto)
            throws IOException {
        byte[] corpo = texto.getBytes(StandardCharsets.UTF_8);
        troca.sendResponseHeaders(status, corpo.length);
        try (OutputStream saida = troca.getResponseBody()) {
            saida.write(corpo);
        }
    }

    @AfterAll
    static void derrubarServidor() {
        servidor.stop(0);
    }

    @Test
    void naoSegueRedirecionamento() throws Exception {
        // Bypass clássico de allowlist: o host autorizado responde 302 para a rede interna.
        // Com Redirect.NEVER o buscador para no 302 e o segredo nunca é lido.
        String corpo = buscador.buscar(URI.create(base + "/salto"));

        assertThat(corpo)
                .as("seguir o redirect entregaria o conteudo interno ao atacante")
                .doesNotContain(SEGREDO);
    }

    @Test
    void cortaCorpoNoLimite() throws Exception {
        String corpo = buscador.buscar(URI.create(base + "/grande"));

        // Tamanho literal de propósito: se alguém mexer no LIMITE_CORPO, o teste reprova e
        // obriga a decisão a ser explícita, em vez de acompanhar a constante em silêncio.
        assertThat(corpo).hasSize(8192);
    }
}
