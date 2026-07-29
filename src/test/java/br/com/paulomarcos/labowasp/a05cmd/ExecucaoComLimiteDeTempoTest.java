package br.com.paulomarcos.labowasp.a05cmd;

import static br.com.paulomarcos.labowasp.a05cmd.CommandInjectionController.WINDOWS;
import static br.com.paulomarcos.labowasp.a05cmd.CommandInjectionController.executar;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * O limite de tempo do executor de processos precisa ser real, não decorativo.
 *
 * <p>Na versão anterior a saída era lida com {@code in.readAllBytes()} antes do {@code waitFor(10,
 * SECONDS)}: como o {@code readAllBytes} só retorna no EOF do stdout do filho, o {@code waitFor}
 * nunca podia disparar. Medido no laboratório rodando: um payload com {@code && ping -n 20} prendia
 * a requisição por 19,3s. Estes testes rodam com limite de 1 segundo para não custar 10s de CI.
 */
class ExecucaoComLimiteDeTempoTest {

    private static final int LIMITE_CURTO_SEGUNDOS = 1;

    /** Um comando que demora muito mais que o limite, nos dois sistemas operacionais. */
    private static List<String> comandoLento() {
        return WINDOWS
                ? List.of("cmd.exe", "/c", "ping -n 30 127.0.0.1 > NUL")
                : List.of("/bin/sh", "-c", "sleep 30");
    }

    private static List<String> comandoRapido() {
        return WINDOWS
                ? List.of("cmd.exe", "/c", "echo pong de exemplo")
                : List.of("/bin/sh", "-c", "echo pong de exemplo");
    }

    @Test
    void comandoLentoEhInterrompidoNoLimiteEmVezDePrenderARequisicao() throws Exception {
        long inicio = System.nanoTime();
        String saida = executar(comandoLento(), LIMITE_CURTO_SEGUNDOS);
        Duration decorrido = Duration.ofNanos(System.nanoTime() - inicio);

        assertThat(saida).isEqualTo("tempo esgotado");
        assertThat(decorrido)
                .as("o waitFor precisa ser o unico ponto de bloqueio; o comando dura 30s")
                .isLessThan(Duration.ofSeconds(10));
    }

    @Test
    void comandoRapidoContinuaDevolvendoASaidaReal() throws Exception {
        // Sem falso positivo: o caminho normal segue entregando o stdout do processo.
        assertThat(executar(comandoRapido(), LIMITE_CURTO_SEGUNDOS)).contains("pong de exemplo");
    }
}
