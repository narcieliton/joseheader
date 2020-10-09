package com.narcielitonlopes.joseheader;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.Assert;
import util.CertificadoUtil;
import util.JoseHeaderUtil;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;

@SpringBootTest
class JoseheaderApplicationTests {

    //caminho onde está o meu certificado
    private String caminhoCertificado = "C:\\Desenvolvimento\\certificado\\certificado.cer";

    @Test
    void contextLoads() {
    }

    @Test
    void obterRSAKeyCertificado() throws FileNotFoundException, JOSEException, CertificateException {
        RSAKey rsaKey = CertificadoUtil.obterRSAKey(caminhoCertificado);
        Assert.notNull(rsaKey, "test obterRSAKeyCertificado");
    }

    @Test
    void montarRequisicao() {
        String token = JoseHeaderUtil.montarRequisicao("jsonPayload", caminhoCertificado);
        Assert.notNull(token, "test montarRequisicao");
    }

    @Test
    void extrairPayloadCertificadoValido() throws FileNotFoundException, JOSEException, CertificateException {
        String joseGerado = JoseHeaderUtil.montarRequisicao("jsonPayload", caminhoCertificado);
        String payload = JoseHeaderUtil.extrairPayloadCertificadoValido(joseGerado, caminhoCertificado);
        Assert.notNull(payload, "test extrairPayloadCertificadoValido");
    }

    @Test
    void validarJoseHeader() {
        String joseGerado = JoseHeaderUtil.montarRequisicao("jsonPayload", caminhoCertificado);
        boolean isJoseHeaderValid =  JoseHeaderUtil.validarJoseHeader(joseGerado, caminhoCertificado);
        Assert.notNull(isJoseHeaderValid, "test validarJoseHeader");
    }
}
