package br.com.paulomarcos.labowasp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Laboratório didático do OWASP Top 10:2025 — 8 vulnerabilidades em 3 categorias (A01, A04, A05).
 *
 * <p>Seis dos oito pares aparecem em dois endpoints: {@code /vulneravel} (a falha) e {@code
 * /corrigido} (a remediação). Os outros dois — Path Traversal ({@code a01path}) e hash de senha
 * ({@code a04crypto}) — são pares de biblioteca, sem rota HTTP, exercitados direto pelo teste. Os
 * testes provam que o exploit funciona na versão vulnerável e é bloqueado na corrigida.
 *
 * <p><b>Uso educativo.</b> A aplicação contém falhas de propósito e só escuta em {@code 127.0.0.1}
 * — ver {@code application.properties} e {@code ConfiguracaoDeRedeTest}.
 */
@SpringBootApplication
public class LabOwaspApplication {

    public static void main(String[] args) {
        SpringApplication.run(LabOwaspApplication.class, args);
        avisar();
    }

    /** Aviso de escopo no console, no mesmo espírito do resto da suíte. */
    private static void avisar() {
        System.out.println(
                """

                ================================================================
                 LABORATORIO OWASP - aplicacao vulneravel DE PROPOSITO
                 Escuta so em 127.0.0.1. Nao publique a porta 8080 em conteiner
                 (-p 127.0.0.1:8080:8080, nunca -p 8080:8080):
                 /a05/cmd/vulneravel executa comandos do sistema operacional,
                 sem autenticacao.
                 Usar estas tecnicas fora daqui, sem autorizacao por escrito, e
                 crime no Brasil (Lei 12.737/2012 c/ Lei 14.155/2021).
                ================================================================
                """);
    }
}
