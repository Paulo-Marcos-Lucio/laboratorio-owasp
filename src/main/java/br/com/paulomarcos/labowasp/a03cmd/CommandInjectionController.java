package br.com.paulomarcos.labowasp.a03cmd;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A03:2021 Injection — OS Command Injection (CWE-78).
 *
 * <p>Um utilitário de diagnóstico que "checa um host" executando um comando do sistema
 * operacional. O {@code /vulneravel} monta a linha de comando concatenando o host recebido
 * e a entrega a um shell ({@code sh -c} / {@code cmd /c}); um host como
 * {@code 127.0.0.1 && echo INVADIDO} faz o shell rodar um segundo comando escolhido pelo
 * atacante. O {@code /corrigido} nunca entrega a entrada a um shell: valida o host contra
 * uma allowlist estrita de caracteres de hostname e recusa qualquer metacaractere.
 *
 * <p>O comando real aqui é um {@code echo} inofensivo (para o laboratório rodar sem rede
 * nem privilégios); numa ferramenta de verdade seria um {@code ping}/{@code nslookup}. A
 * falha e a correção são idênticas: o problema é entregar entrada do usuário ao shell.
 */
@RestController
@RequestMapping("/a03/cmd")
public class CommandInjectionController {

    /** Hostname válido: letras, dígitos, ponto, hífen e sublinhado. Sem espaço nem metacaracteres de shell. */
    private static final Pattern HOST_VALIDO = Pattern.compile("^[A-Za-z0-9._-]{1,253}$");

    private static final boolean WINDOWS =
            System.getProperty("os.name", "").toLowerCase().contains("win");

    @GetMapping("/vulneravel")
    public String vulneravel(@RequestParam String host) throws IOException, InterruptedException {
        // NUNCA faça isto: o host é concatenado na linha de comando e entregue a um shell,
        // que interpreta ;, &&, |, `...` etc. como comandos adicionais do atacante.
        String comando = "echo pong de " + host;
        List<String> argv =
                WINDOWS ? List.of("cmd.exe", "/c", comando) : List.of("/bin/sh", "-c", comando);
        return executar(argv);
    }

    @GetMapping("/corrigido")
    public ResponseEntity<String> corrigido(@RequestParam String host) {
        if (!HOST_VALIDO.matcher(host).matches()) {
            // Entrada com metacaractere (ou vazia/longa demais): recusa antes de qualquer execução.
            return ResponseEntity.badRequest().body("host invalido");
        }
        // A entrada passou na allowlist e NUNCA toca um shell: a resposta é montada em Java.
        // Princípio correto: não entregar dados do usuário a um interpretador de comandos.
        return ResponseEntity.ok("pong de " + host);
    }

    /** Roda o processo, junta stdout+stderr e limita o tempo para o laboratório nunca travar. */
    private static String executar(List<String> argv) throws IOException, InterruptedException {
        Process processo = new ProcessBuilder(argv).redirectErrorStream(true).start();
        String saida;
        try (InputStream in = processo.getInputStream()) {
            saida = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        if (!processo.waitFor(10, TimeUnit.SECONDS)) {
            processo.destroyForcibly();
        }
        return saida;
    }
}
