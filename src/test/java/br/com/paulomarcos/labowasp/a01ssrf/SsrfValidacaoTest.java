package br.com.paulomarcos.labowasp.a01ssrf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

/**
 * Testes de unidade da classificação de endereço interno, nos dois sentidos, sem Spring nem rede.
 * {@link InetAddress#getByName} sobre um literal de IP apenas o interpreta — não faz DNS —, então
 * nenhum destes toca a internet.
 */
class SsrfValidacaoTest {

    @Test
    void enderecosInternosSaoBloqueados() throws UnknownHostException {
        String[] internos = {
            "127.0.0.1", // loopback
            "::1", // loopback IPv6
            "0.0.0.0", // curinga
            "169.254.169.254", // link-local (metadados de nuvem)
            "10.0.0.5", // privado 10/8
            "172.16.0.1", // privado 172.16/12
            "192.168.1.1", // privado 192.168/16
            "fd00::1" // unique-local IPv6 (fc00::/7)
        };
        for (String ip : internos) {
            assertTrue(
                    SsrfController.ehEnderecoInterno(InetAddress.getByName(ip)),
                    ip + " deveria ser tratado como interno");
        }
    }

    @Test
    void enderecosPublicosSaoPermitidos() throws UnknownHostException {
        String[] publicos = {
            "8.8.8.8", // DNS público Google
            "1.1.1.1", // DNS público Cloudflare
            "203.0.113.10", // TEST-NET-3 (documentação, público)
            "2606:4700:4700::1111" // Cloudflare DNS IPv6
        };
        for (String ip : publicos) {
            assertFalse(
                    SsrfController.ehEnderecoInterno(InetAddress.getByName(ip)),
                    ip + " NAO deveria ser tratado como interno");
        }
    }
}
