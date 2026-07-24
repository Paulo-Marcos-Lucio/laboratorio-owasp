package br.com.paulomarcos.labowasp.a10ssrf;

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
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A10:2021 Server-Side Request Forgery — SSRF (CWE-918).
 *
 * <p>Um recurso comum de "buscar o conteúdo desta URL" (preview de link, webhook, importar
 * imagem por URL). O {@code /vulneravel} busca <b>qualquer</b> URL que o usuário mandar —
 * então {@code ?url=http://127.0.0.1:.../interno} ou
 * {@code ?url=http://169.254.169.254/latest/meta-data/} faz o <b>servidor</b> alcançar
 * serviços internos e o endpoint de metadados da nuvem (AWS/GCP/Azure), vazando dados que
 * o atacante não alcançaria de fora.
 *
 * <p>O {@code /corrigido} aplica duas camadas: (1) uma <b>allowlist</b> de host + só os
 * esquemas {@code http}/{@code https}; e (2), como defesa em profundidade contra host
 * permitido que resolva para dentro (DNS rebinding, split-horizon), resolve o host e
 * <b>recusa qualquer endereço interno</b> — loopback, {@code 0.0.0.0}, link-local
 * (169.254/16, inclui o IP de metadados), privado (10/8, 172.16/12, 192.168/16),
 * multicast e unique-local IPv6 (fc00::/7).
 */
@RestController
@RequestMapping("/a10/ssrf")
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
    public ResponseEntity<String> vulneravel(@RequestParam String url)
            throws IOException, InterruptedException {
        // NUNCA faça isto: o servidor busca uma URL crua do usuário, sem validar host nem
        // esquema. Isso alcança 127.0.0.1, a rede interna e 169.254.169.254 (metadados).
        String corpo = buscador.buscar(URI.create(url));
        return ResponseEntity.ok(corpo);
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
                // dentro (rebinding/split-horizon), recusa antes de qualquer requisição.
                return ResponseEntity.badRequest().body("destino interno bloqueado");
            }
        }

        // Passou nas duas camadas: é um host permitido que resolve para um endereço público.
        String corpo = buscador.buscar(uri);
        return ResponseEntity.ok(corpo);
    }

    /**
     * Verdadeiro para qualquer endereço que não deva ser alcançado a partir de uma URL
     * fornecida pelo usuário: loopback, curinga ({@code 0.0.0.0}/{@code ::}), link-local
     * (169.254/16 e fe80::/10 — inclui o IP de metadados de nuvem), privado
     * (10/8, 172.16/12, 192.168/16), multicast e unique-local IPv6 (fc00::/7).
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
