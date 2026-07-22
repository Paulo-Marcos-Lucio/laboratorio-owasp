package br.com.paulomarcos.labowasp.a01idor;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A01:2021 Broken Access Control — IDOR (CWE-639).
 *
 * <p>O {@code /vulneravel} devolve qualquer nota pelo id, sem verificar se ela
 * pertence a quem pede — trocar o id no navegador dá acesso a dados alheios. O
 * {@code /corrigido} valida a propriedade antes de responder.
 */
@RestController
@RequestMapping("/a01/idor")
public class IdorController {

    private final Map<Long, Nota> notas = Map.of(
            1L, new Nota(1L, "alice", "Dados bancarios da Alice"),
            2L, new Nota(2L, "bob", "Anotacoes do Bob"));

    @GetMapping("/vulneravel/{id}")
    public ResponseEntity<Nota> vulneravel(
            @PathVariable long id, @RequestHeader("X-Usuario") String usuario) {
        Nota nota = notas.get(id);
        if (nota == null) {
            // id inexistente é 404 — não 200 com corpo vazio (fail-silent).
            return ResponseEntity.notFound().build();
        }
        // IDOR preservado de propósito: NÃO confere o dono — qualquer usuário lê a nota alheia.
        return ResponseEntity.ok(nota);
    }

    @GetMapping("/corrigido/{id}")
    public ResponseEntity<Nota> corrigido(
            @PathVariable long id, @RequestHeader("X-Usuario") String usuario) {
        Nota nota = notas.get(id);
        if (nota == null) {
            return ResponseEntity.notFound().build();
        }
        if (!nota.dono().equals(usuario)) {
            // Autorização baseada em propriedade do recurso.
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(nota);
    }
}
