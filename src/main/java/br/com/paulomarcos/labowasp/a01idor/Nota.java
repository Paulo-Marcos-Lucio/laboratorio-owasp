package br.com.paulomarcos.labowasp.a01idor;

/** Uma nota privada, pertencente a um usuário. */
public record Nota(long id, String dono, String texto) {}
