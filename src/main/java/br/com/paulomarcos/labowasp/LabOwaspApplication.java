package br.com.paulomarcos.labowasp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Laboratório didático de OWASP Top 10.
 *
 * <p>Cada vulnerabilidade aparece em dois endpoints: {@code /vulneravel} (a falha)
 * e {@code /corrigido} (a remediação). Os testes provam que o exploit funciona na
 * versão vulnerável e é bloqueado na corrigida.
 *
 * <p><b>Uso educativo.</b> A aplicação contém falhas de propósito — não exponha na
 * internet.
 */
@SpringBootApplication
public class LabOwaspApplication {

    public static void main(String[] args) {
        SpringApplication.run(LabOwaspApplication.class, args);
    }
}
