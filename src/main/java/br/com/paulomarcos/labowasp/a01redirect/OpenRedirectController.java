package br.com.paulomarcos.labowasp.a01redirect;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A01:2021 Broken Access Control — Open Redirect (CWE-601).
 *
 * <p>Um padrão comum de "voltar para onde eu estava" após login: o destino vem num
 * parâmetro. O {@code /vulneravel} redireciona para qualquer valor recebido — um link
 * {@code ?destino=https://site-falso.example} leva a vítima para fora do domínio, base
 * clássica de phishing. O {@code /corrigido} só aceita caminhos relativos ao próprio
 * app, recusando URLs absolutas e as variações que os navegadores tratam como externas
 * ({@code //host}, {@code /\host}, {@code \\host}).
 */
@RestController
@RequestMapping("/a01/redirect")
public class OpenRedirectController {

    @GetMapping("/vulneravel")
    public ResponseEntity<Void> vulneravel(@RequestParam String destino) {
        // NUNCA faça isto: o destino do redirect vem cru do usuário, sem validação.
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(destino)).build();
    }

    @GetMapping("/corrigido")
    public ResponseEntity<Void> corrigido(@RequestParam String destino) {
        if (!ehCaminhoRelativoSeguro(destino)) {
            // Destino externo (ou disfarçado de relativo): recusa em vez de redirecionar.
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(destino)).build();
    }

    /**
     * Só é seguro um caminho relativo à raiz do próprio app: começa com uma única barra
     * e não com as sequências que o navegador interpreta como host externo.
     *
     * <ul>
     *   <li>{@code //host} — URL protocolo-relativa (vira {@code https://host}).
     *   <li>{@code /\host} e {@code \\host} — a barra invertida é normalizada para barra
     *       por muitos navegadores, virando protocolo-relativa.
     *   <li>{@code https://host} — URL absoluta explícita.
     * </ul>
     */
    private static boolean ehCaminhoRelativoSeguro(String destino) {
        if (destino == null || destino.length() < 2) {
            return false;
        }
        char primeiro = destino.charAt(0);
        char segundo = destino.charAt(1);
        // Precisa começar em "/" (caminho absoluto no próprio host)...
        if (primeiro != '/') {
            return false;
        }
        // ...mas nao pode ser "//" nem "/\" (ambos viram host externo no navegador).
        if (segundo == '/' || segundo == '\\') {
            return false;
        }
        return true;
    }
}
