package br.com.paulomarcos.labowasp.a05cmd;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A05:2025 Injection — OS Command Injection (CWE-78).
 *
 * <p>Um utilitário de diagnóstico que "checa um host" executando um comando do sistema operacional.
 * O {@code /vulneravel} monta a linha de comando concatenando o host recebido e a entrega a um
 * shell ({@code sh -c} / {@code cmd /c}); um host como {@code 127.0.0.1 && echo INVADIDO} faz o
 * shell rodar um segundo comando escolhido pelo atacante. O {@code /corrigido} nunca entrega a
 * entrada a um shell: valida o host contra uma allowlist estrita de caracteres de hostname e recusa
 * qualquer metacaractere.
 *
 * <p>O comando real aqui é um {@code echo} inofensivo (para o laboratório rodar sem rede nem
 * privilégios); numa ferramenta de verdade seria um {@code ping}/{@code nslookup}. A falha e a
 * correção são idênticas: o problema é entregar entrada do usuário ao shell.
 */
@RestController
@RequestMapping("/a05/cmd")
public class CommandInjectionController {

    /**
     * Hostname válido: letras, dígitos, ponto, hífen e sublinhado. Sem espaço nem metacaracteres de
     * shell.
     */
    private static final Pattern HOST_VALIDO = Pattern.compile("^[A-Za-z0-9._-]{1,253}$");

    static final boolean WINDOWS =
            System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

    /** Tempo máximo do processo filho. Ver {@link #executar(List, int)}. */
    static final int LIMITE_SEGUNDOS = 10;

    @GetMapping("/vulneravel")
    public String vulneravel(@RequestParam String host) throws IOException, InterruptedException {
        // NUNCA faça isto: o host é concatenado na linha de comando e entregue a um shell,
        // que interpreta ;, &&, |, `...` etc. como comandos adicionais do atacante.
        String comando = "echo pong de " + host;
        List<String> argv =
                WINDOWS ? List.of("cmd.exe", "/c", comando) : List.of("/bin/sh", "-c", comando);
        return executar(argv, LIMITE_SEGUNDOS);
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

    /**
     * Roda o processo, junta stdout+stderr e devolve {@code "tempo esgotado"} se ele passar de
     * {@code limiteSegundos}.
     *
     * <p>A saída vai para um arquivo temporário em vez de ser lida do {@code InputStream} do
     * processo. O motivo é o erro clássico deste padrão em Java: {@code readAllBytes()} bloqueia
     * até o EOF do stdout do filho, ou seja, até o processo terminar — o {@code waitFor(10,
     * SECONDS)} depois dele nunca tem como disparar. Medido: um payload com {@code && ping -n 20}
     * prendia a requisição por 19,3s com um "timeout de 10s" escrito no código. Redirecionando a
     * saída, o {@code waitFor} passa a ser o único ponto de bloqueio e o limite vale de verdade.
     */
    static String executar(List<String> argv, int limiteSegundos)
            throws IOException, InterruptedException {
        Path saidaTemp = Files.createTempFile("labowasp-cmd-", ".txt");
        try {
            Process processo =
                    new ProcessBuilder(argv)
                            .redirectErrorStream(true)
                            .redirectOutput(saidaTemp.toFile())
                            .start();
            if (!processo.waitFor(limiteSegundos, TimeUnit.SECONDS)) {
                // Matar só o processo iniciado mata apenas o SHELL: o segundo comando que o
                // atacante encadeou ("&& sleep 3600") continuaria rodando como órfão,
                // segurando CPU e o arquivo de saída. Os descendentes vêm primeiro.
                processo.descendants().forEach(ProcessHandle::destroyForcibly);
                processo.destroyForcibly().waitFor();
                return "tempo esgotado";
            }
            return Files.readString(saidaTemp, StandardCharsets.UTF_8);
        } finally {
            try {
                Files.deleteIfExists(saidaTemp);
            } catch (IOException e) {
                // No Windows o handle pode demorar a ser liberado depois do kill; o arquivo
                // temporário some no encerramento da JVM.
                saidaTemp.toFile().deleteOnExit();
            }
        }
    }
}
