package br.com.paulomarcos.labowasp.a01path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ArquivoServiceTest {

    private final ArquivoService service = new ArquivoService();

    @Test
    void vulneravelEscapaComDotDot(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectory(tmp.resolve("publicos"));
        Files.writeString(tmp.resolve("segredo.txt"), "SENHA_SECRETA");

        // "../segredo.txt" sai do diretório-base e lê o arquivo secreto.
        String vazado = service.lerVulneravel(base, "../segredo.txt");
        assertThat(vazado).isEqualTo("SENHA_SECRETA");
    }

    @Test
    void corrigidoBloqueiaDotDot(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectory(tmp.resolve("publicos"));
        Files.writeString(tmp.resolve("segredo.txt"), "SENHA_SECRETA");

        assertThatThrownBy(() -> service.lerCorrigido(base, "../segredo.txt"))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void corrigidoPermiteArquivoInterno(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectory(tmp.resolve("publicos"));
        Files.writeString(base.resolve("catalogo.txt"), "conteudo ok");

        assertThat(service.lerCorrigido(base, "catalogo.txt")).isEqualTo("conteudo ok");
    }

    // Regressão: com um base RELATIVO contendo ".." inicial, normalizar antes de tornar
    // absoluto deixava o ".." na base e recusava um arquivo legítimo. A ordem correta
    // (toAbsolutePath().normalize()) resolve o caminho e o arquivo passa a ser aceito.
    @Test
    void corrigidoAceitaArquivoInternoComBaseRelativaComDotDot(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectory(tmp.resolve("publicos"));
        Files.writeString(base.resolve("catalogo.txt"), "conteudo ok");

        Path cwd = Path.of("").toAbsolutePath();
        assumeTrue(
                base.getRoot() != null && base.getRoot().equals(cwd.getRoot()),
                "base e CWD em roots diferentes — cenário de caminho relativo não se aplica");
        Path baseRelativa = cwd.relativize(base);
        assumeTrue(baseRelativa.startsWith(".."), "não gerou base relativa com '..' inicial");

        assertThat(service.lerCorrigido(baseRelativa, "catalogo.txt")).isEqualTo("conteudo ok");
    }
}
