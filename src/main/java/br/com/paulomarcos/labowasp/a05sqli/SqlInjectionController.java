package br.com.paulomarcos.labowasp.a05sqli;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A05:2025 Injection — SQL Injection (CWE-89).
 *
 * <p>O endpoint {@code /vulneravel} concatena a entrada do usuário direto na query; uma entrada
 * como {@code Notebook' OR '1'='1} retorna a tabela inteira. O {@code /corrigido} usa consulta
 * parametrizada, onde a entrada é sempre um valor, nunca código SQL.
 */
@RestController
@RequestMapping("/a05/sqli")
public class SqlInjectionController {

    private final JdbcTemplate jdbc;

    public SqlInjectionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/vulneravel")
    public List<Map<String, Object>> vulneravel(@RequestParam String nome) {
        // NUNCA faça isto: a entrada vira parte do comando SQL.
        String sql = "SELECT id, nome, preco FROM produtos WHERE nome = '" + nome + "'";
        return jdbc.queryForList(sql);
    }

    @GetMapping("/corrigido")
    public List<Map<String, Object>> corrigido(@RequestParam String nome) {
        // A entrada é um parâmetro ligado (bind), tratado como dado, não como código.
        String sql = "SELECT id, nome, preco FROM produtos WHERE nome = ?";
        return jdbc.queryForList(sql, nome);
    }
}
