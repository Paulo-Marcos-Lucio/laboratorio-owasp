package br.com.paulomarcos.labowasp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.paulomarcos.labowasp.a01path.ArquivoService;
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
}
