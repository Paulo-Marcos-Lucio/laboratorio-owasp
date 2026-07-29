package br.com.paulomarcos.labowasp.a01ssrf;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A01:2025 Broken Access Control — SSRF (CWE-918).
 *
 * <p>Um recurso comum de "buscar o conteúdo desta URL" (preview de link, webhook, importar imagem
 * por URL). O {@code /vulneravel} busca <b>qualquer</b> URL que o usuário mandar — então {@code
 * ?url=http://127.0.0.1:.../interno} ou {@code ?url=http://169.254.169.254/latest/meta-data/} faz o
 * <b>servidor</b> alcançar serviços internos e o endpoint de metadados da nuvem (AWS/GCP/Azure),
 * vazando dados que o atacante não alcançaria de fora.
 *
 * <p>O {@code /corrigido} aplica duas camadas: (1) uma <b>allowlist</b> de host + só os esquemas
 * {@code http}/{@code https}; e (2), como defesa em profundidade, resolve o host e <b>recusa
 * qualquer endereço interno</b> — loopback, {@code 0.0.0.0}, link-local (169.254/16, inclui o IP de
 * metadados), privado (10/8, 172.16/12, 192.168/16), multicast e unique-local IPv6 (fc00::/7).
 *
 * <p><b>O que a camada 2 NÃO faz: ela não impede DNS rebinding.</b> A validação e a busca resolvem
 * o nome de forma independente — a linha da validação chama {@link
 * java.net.InetAddress#getAllByName} e o {@code buscador.buscar(uri)} depois resolve o host da URI
 * <i>de novo</i>, descartando o endereço já validado. É um check-then-use (TOCTOU) clássico: se a
 * resposta de DNS mudar entre as duas resoluções, a camada 2 aprova um IP público e a conexão sai
 * para o IP interno. Isso está reproduzido em {@code SsrfLimiteRebindingTest}, que documenta o
 * vazamento em vez de fingir que ele não existe. Contra <b>configuração estática</b> —
 * split-horizon, allowlist com um host que sempre aponta para dentro — a camada 2 funciona, e é
 * para isso que ela serve aqui.
 *
 * <p>A mitigação de verdade contra rebinding é conectar no <b>endereço já validado</b> (fixar o IP
 * e mandar o hostname original em {@code Host}/SNI) ou sair por um proxy de egresso com allowlist —
 * nenhuma das duas cabe neste laboratório sem esconder a lição.
 */
@RestController
@RequestMapping("/a01/ssrf")
public class SsrfController {

    private final HttpBuscador buscador;
    private final Set<String> allowlist;

    public SsrfController(
            HttpBuscador buscador,
            @Value("${ssrf.allowlist:api.exemplo.com,cdn.exemplo.com}") List<String> allowlist) {
        this.buscador = buscador;
        this.allowlist =
                allowlist.stream()
                        .map(host -> host.trim().toLowerCase(Locale.ROOT))
                        .filter(host -> !host.isEmpty())
                        .collect(Collectors.toUnmodifiableSet());
    }

    @GetMapping("/vulneravel")
    public ResponseEntity<String> vulneravel(@RequestParam String url) throws InterruptedException {
        // NUNCA faça isto: o servidor busca uma URL crua do usuário, sem validar host nem
        // esquema. Isso alcança 127.0.0.1, a rede interna e 169.254.169.254 (metadados).
        try {
            return ResponseEntity.ok(buscador.buscar(URI.create(url)));
        } catch (IOException | IllegalArgumentException e) {
            // O SSRF continua inteiro (basta a URL responder). O que muda é que um destino
            // que não responde — 169.254.169.254 fora de uma nuvem, por exemplo — devolve
            // 502 com o motivo, em vez de um 500 opaco que esconde a lição.
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("nao foi possivel buscar a URL: " + e.getMessage());
        }
    }

    @GetMapping("/corrigido")
    public ResponseEntity<String> corrigido(@RequestParam String url)
            throws IOException, InterruptedException {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return ResponseEntity.badRequest().body("url malformada");
        }

        String esquema = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!esquema.equals("http") && !esquema.equals("https")) {
            // Só http/https: barra file:, gopher:, ftp:, dict: etc., vetores clássicos de SSRF.
            return ResponseEntity.badRequest().body("esquema nao permitido");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            return ResponseEntity.badRequest().body("host ausente");
        }
        if (!allowlist.contains(host.toLowerCase(Locale.ROOT))) {
            // Camada 1: só hosts explicitamente autorizados podem ser buscados.
            return ResponseEntity.badRequest().body("host fora da allowlist");
        }

        InetAddress[] enderecos;
        try {
            enderecos = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return ResponseEntity.badRequest().body("host nao resolve");
        }
        for (InetAddress endereco : enderecos) {
            if (ehEnderecoInterno(endereco)) {
                // Camada 2 (defesa em profundidade): mesmo permitido, se resolve para
                // dentro (split-horizon, allowlist mal configurada), recusa antes de
                // qualquer requisição.
                return ResponseEntity.badRequest().body("destino interno bloqueado");
            }
        }

        // Passou nas duas camadas. ATENÇÃO — aqui mora o limite documentado no javadoc: a
        // busca recebe a URI e resolve o host DE NOVO; o array `enderecos` que acabou de ser
        // validado é descartado. É o que permite o DNS rebinding.
        String corpo = buscador.buscar(uri);
        return ResponseEntity.ok(corpo);
    }

    /**
     * Verdadeiro para qualquer endereço que não deva ser alcançado a partir de uma URL fornecida
     * pelo usuário: loopback, curinga ({@code 0.0.0.0}/{@code ::}), link-local (169.254/16 e
     * fe80::/10 — inclui o IP de metadados de nuvem), privado (10/8, 172.16/12, 192.168/16),
     * multicast e unique-local IPv6 (fc00::/7).
     */
    static boolean ehEnderecoInterno(InetAddress endereco) {
        return endereco.isLoopbackAddress()
                || endereco.isAnyLocalAddress()
                || endereco.isLinkLocalAddress()
                || endereco.isSiteLocalAddress()
                || endereco.isMulticastAddress()
                || ehUniqueLocalIpv6(endereco);
    }

    /** fc00::/7 — o "privado" do IPv6, que {@link InetAddress} não classifica sozinho. */
    private static boolean ehUniqueLocalIpv6(InetAddress endereco) {
        byte[] octetos = endereco.getAddress();
        return octetos.length == 16 && (octetos[0] & 0xfe) == 0xfc;
    }
}
