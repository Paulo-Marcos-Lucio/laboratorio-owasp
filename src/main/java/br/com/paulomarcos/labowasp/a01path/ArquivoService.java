package br.com.paulomarcos.labowasp.a01path;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Service;

/**
 * A01:2021 Broken Access Control — Path Traversal (CWE-22).
 *
 * <p>{@link #lerVulneravel} resolve o nome de arquivo recebido direto sobre o
 * diretório-base: um nome como {@code ../../etc/passwd} escapa do diretório e lê
 * arquivos arbitrários. {@link #lerCorrigido} normaliza o caminho e recusa
 * qualquer resultado que não permaneça dentro do diretório permitido.
 */
@Service
public class ArquivoService {

    public String lerVulneravel(Path base, String nome) throws IOException {
        // resolve() aceita "../" e sai do diretório-base.
        return Files.readString(base.resolve(nome));
    }

    public String lerCorrigido(Path base, String nome) throws IOException {
        // toAbsolutePath() ANTES de normalize(): um base relativo com ".." inicial só
        // resolve corretamente depois de virar absoluto — a ordem trocada deixava o
        // ".." na base e passava a recusar arquivos legítimos.
        Path baseNormalizado = base.toAbsolutePath().normalize();
        Path alvo = baseNormalizado.resolve(nome).normalize();
        if (!alvo.startsWith(baseNormalizado)) {
            throw new SecurityException("Acesso negado: caminho fora do diretorio permitido");
        }
        return Files.readString(alvo);
    }
}
