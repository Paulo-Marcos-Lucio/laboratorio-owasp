package br.com.paulomarcos.labowasp.a01redirect;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A01:2025 Broken Access Control — Open Redirect (CWE-601).
 *
 * <p>Um padrão comum de "voltar para onde eu estava" após login: o destino vem num parâmetro. O
 * {@code /vulneravel} redireciona para qualquer valor recebido — um link {@code
 * ?destino=https://site-falso.example} leva a vítima para fora do domínio, base clássica de
 * phishing. O {@code /corrigido} só aceita caminhos relativos ao próprio app, recusando URLs
 * absolutas e as variações que os navegadores tratam como externas ({@code //host}, {@code /\host},
 * {@code \\host}).
 */
@RestController
@RequestMapping("/a01/redirect")
public class OpenRedirectController {

    @GetMapping("/vulneravel")
    public ResponseEntity<Void> vulneravel(@RequestParam String destino) {
        // NUNCA faça isto: o destino do redirect vem cru do usuário, sem validação.
        // (O try/catch NÃO é a correção — o Open Redirect segue aqui de propósito. Ele só
        // evita que uma entrada que nem é URI vire um 500 e esconda a lição atrás de um
        // erro genérico do servidor.)
        URI localizacao = tentarConverter(destino);
        if (localizacao == null) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(localizacao).build();
    }

    @GetMapping("/corrigido")
    public ResponseEntity<Void> corrigido(@RequestParam String destino) {
        if (!ehCaminhoRelativoSeguro(destino)) {
            // Destino externo (ou disfarçado de relativo): recusa em vez de redirecionar.
            return ResponseEntity.badRequest().build();
        }
        URI localizacao = tentarConverter(destino);
        if (localizacao == null) {
            // Passou na validação de forma mas não é um URI válido (ex.: "/meu painel", com
            // espaço). Recusar com 400 é a resposta certa — devolver 500 seria transformar
            // entrada trivial do usuário em erro do servidor.
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(localizacao).build();
    }

    /** Devolve o {@link URI} ou {@code null} se a entrada não for sequer um URI válido. */
    private static URI tentarConverter(String destino) {
        try {
            return URI.create(destino);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Só é seguro um caminho relativo à raiz do próprio app: começa com uma única barra e não com
     * as sequências que o navegador interpreta como host externo.
     *
     * <ul>
     *   <li>{@code //host} — URL protocolo-relativa (vira {@code https://host}).
     *   <li>{@code /\host} e {@code \\host} — a barra invertida é normalizada para barra por muitos
     *       navegadores, virando protocolo-relativa.
     *   <li>{@code https://host} — URL absoluta explícita.
     * </ul>
     */
    private static boolean ehCaminhoRelativoSeguro(String destino) {
        if (destino == null || destino.isEmpty()) {
            return false;
        }
        // Precisa começar em "/" (caminho absoluto no próprio host)...
        if (destino.charAt(0) != '/') {
            return false;
        }
        // ...mas nao pode ser "//" nem "/\" (ambos viram host externo no navegador).
        // O segundo caractere só é lido se existir: "/" sozinho é a raiz do próprio app,
        // o destino pós-login mais comum que existe, e precisa ser aceito.
        if (destino.length() > 1) {
            char segundo = destino.charAt(1);
            if (segundo == '/' || segundo == '\\') {
                return false;
            }
        }
        return true;
    }
}
