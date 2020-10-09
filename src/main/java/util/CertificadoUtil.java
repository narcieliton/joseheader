package util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class CertificadoUtil {

    public static RSAKey obterRSAKey(String nomeCaminhoCertificado) throws JOSEException, FileNotFoundException, CertificateException {
        RSAKey key;
        FileInputStream entrada = obterArquivoCertificado(nomeCaminhoCertificado);
        CertificateFactory cf = obterCertificateFactory();
        X509Certificate x509Certificate;
        try {
            if(cf != null) {
                x509Certificate = (X509Certificate) cf.generateCertificate(entrada);
            }else {
                throw new FileNotFoundException("Certificado não encontrado no caminho informado!");
            }
            key = RSAKey.parse(x509Certificate);
        } catch (JOSEException e) {
            throw new JOSEException("Erro ao fazer parse de x509Certificate para RSAKey: " + e.getMessage());
        }
        catch (CertificateException e) {
            throw new CertificateException("Erro ao gerar o Certificado: " + nomeCaminhoCertificado + " " + e.getMessage());
        }
        return key;
    }

    private static FileInputStream obterArquivoCertificado(String nomeCaminhoCertificado) throws FileNotFoundException {
        FileInputStream fileInputStreamCertificado;
        try {
            File certificado = new File(nomeCaminhoCertificado);
            fileInputStreamCertificado = new FileInputStream(certificado);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("Certificado não encontrado com o caminho e nome informado " + nomeCaminhoCertificado + " " + e.getMessage());
        }
        return fileInputStreamCertificado;
    }

    private static CertificateFactory obterCertificateFactory() {
        CertificateFactory cf = null;
        try {
            cf =  CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            System.out.println("Erro ao pegar intancia CertificateFactory: " + e.getMessage());
        }
        return cf;
    }

}
