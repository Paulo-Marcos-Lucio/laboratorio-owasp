package br.com.paulomarcos.labowasp.a01ssrf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Resolvedor de DNS de laboratório que simula um atacante fazendo DNS rebinding.
 *
 * <p>Só interfere no nome {@link #HOST}: a primeira consulta devolve um endereço público
 * (203.0.113.10, TEST-NET-3) e todas as seguintes devolvem {@code 127.0.0.1}. Qualquer outro nome é
 * delegado ao resolvedor embutido da JVM, então nenhum outro teste é afetado.
 *
 * <p>É registrado por {@code META-INF/services/java.net.spi.InetAddressResolverProvider} e vale só
 * para o classpath de teste. Usado por {@code SsrfLimiteRebindingTest}.
 */
public final class ResolvedorDeRebinding extends InetAddressResolverProvider {

    /** O único nome que este resolvedor intercepta. */
    public static final String HOST = "rebind.example.com";

    private static final AtomicInteger CONSULTAS = new AtomicInteger();

    /** Quantas vezes {@link #HOST} foi resolvido — o contador que expõe o TOCTOU. */
    public static int consultas() {
        return CONSULTAS.get();
    }

    @Override
    public InetAddressResolver get(Configuration configuracao) {
        InetAddressResolver embutido = configuracao.builtinResolver();
        return new InetAddressResolver() {

            @Override
            public Stream<InetAddress> lookupByName(String nome, LookupPolicy politica)
                    throws UnknownHostException {
                if (!HOST.equalsIgnoreCase(nome)) {
                    return embutido.lookupByName(nome, politica);
                }
                byte[] octetos =
                        CONSULTAS.incrementAndGet() == 1
                                ? new byte[] {(byte) 203, 0, 113, 10} // público: passa na camada 2
                                : new byte[] {127, 0, 0, 1}; // interno: é para onde a conexão vai
                return Stream.of(InetAddress.getByAddress(nome, octetos));
            }

            @Override
            public String lookupByAddress(byte[] endereco) throws UnknownHostException {
                return embutido.lookupByAddress(endereco);
            }
        };
    }

    @Override
    public String name() {
        return "resolvedor-de-rebinding-do-laboratorio";
    }
}
