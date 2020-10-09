package util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public final class JoseHeaderUtil {


    /**
     * Gera a string jws com os parametros necessarios.
     * neste caso  utiliza o gerador de chave utilizando o kid do certificado, gera assinatura e assina o json criado
     *  retornando o serializavel para que seja transmitido via cabeçalho x-jws-signature
     * */
    public static String montarRequisicao(String jsonPayload, String caminhoCertificado) {
        String jwsToken = null;
        try {
            RSAKey rsaKey = CertificadoUtil.obterRSAKey(caminhoCertificado);

            // cria os parametros customizados caso seja necessario enviar urls e ids
            Map<String, Object> customParam = obterCustomParam();

            if(rsaKey != null && !customParam.containsKey(null)) {

                // gera uma chave utilizando 2048 para o sha256RSA e o keykid do certificado local
                RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID(rsaKey.getKeyID()).generate();

                // Cria um signatário RSA com a chave privada
                JWSSigner signer = new RSASSASigner(rsaJWK);
                // Prepare o objeto JWS com string simples como carga útil
                JWSObject jwsObject = new JWSObject(
                        //escolhe o algortimo para gerar o jws nesse caso é o RS256 que é equivalente ao algoritmo de assinatura sha256RSA
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                         //incli o keykid do certificado local no jws
                         .keyID(rsaJWK.getKeyID())
                         // tira um print da chave do certificado  no jws
                        .x509CertSHA256Thumbprint(rsaKey.getX509CertSHA256Thumbprint())
                         //acrestenta as urls com parametros no jws
                        .customParams(customParam)
                         //constroi o jws
                        .build(),
                        //inclui um json do payload
                        new Payload(jsonPayload));

                // assina o objeto jws
                jwsObject.sign(signer);
                // serializa e se torna string para ser enviado na requisicao do cabecalho como x-jws-signature
                jwsToken = jwsObject.serialize();
            }else {
                System.out.println("CustomParam para header: " + customParam + " Erro ao obter o RsaKey do certificado local." + rsaKey);
            }
        } catch (JOSEException e) {
            System.out.println("Erro ao criptografar JSON." + e.getMessage());
        } catch (FileNotFoundException | CertificateException e) {
            System.out.println(e.getMessage());
        }
        return jwsToken;
    }

    public static String extrairPayloadCertificadoValido(String joseHeader, String caminhoCertificado) throws FileNotFoundException, CertificateException, JOSEException {
        JOSEObject joseObject = converterStringJoseHeaderParaJoseObject(joseHeader);
        if(verificarAssinatura(joseObject, joseHeader, caminhoCertificado)){
            System.out.println("assinatura verificada com sucesso");
            return joseObject.getPayload().toString();
        }
        return null;
    }

    /**
     * validar joseHeader convertendo e chamando o metodo para verificar se a assinatura é valida conforme o contrato
     * **/
    public static boolean validarJoseHeader(String joseHeader, String caminhoCertificado) {
        boolean valido = false;
        try{
            JOSEObject joseObject = converterStringJoseHeaderParaJoseObject(joseHeader);
            if(verificarAssinatura(joseObject, joseHeader, caminhoCertificado)){
                valido = true;
            }
        } catch (FileNotFoundException | CertificateException | JOSEException e) {
            System.out.println(e.getMessage());
        }
        return valido;
    }

    private static Map<String, Object> obterCustomParam() {
        Map<String, Object> customParam = new HashMap<>();
        customParam.put("http://www.example.com.br/", "exemple1");
        return customParam;
    }

    private static JOSEObject converterStringJoseHeaderParaJoseObject(String joseHeader) {
        JOSEObject joseObject = null;
        try {
            joseObject = JOSEObject.parse(joseHeader);
        } catch (ParseException e) {
            System.out.println("Erro ao fazer parse do header para SignedJWT. " +  e.getMessage());
        }
        return joseObject;
    }

    private static boolean verificarAssinatura(JOSEObject joseObject, String joseHeader, String caminhoCertificado) throws JOSEException, FileNotFoundException, CertificateException{
        boolean valido = false;
        //caminho onde está o certificado com chave local para validar o certificado com cahve enviado no joseHeader
        RSAKey rsaKey = CertificadoUtil.obterRSAKey(caminhoCertificado);
        String kid = null;

        SignedJWT signedJWT = parseJoseHeader(joseHeader);
        if (signedJWT != null) {
            if (JWSObject.State.SIGNED.equals(signedJWT.getState())) {
                JSONObject jsObjectHeader = joseObject.getHeader().toJSONObject();
                kid = jsObjectHeader.getAsString("kid");
                valido = validarAssinaturaCertificado(rsaKey, kid);
            } else {
                System.out.println("Certificado CIP não assinado para o kid: " + kid);
            }
        }
        return valido;
    }

    private static boolean validarAssinaturaCertificado(RSAKey rsaKeyLocal, String keyIdRecebido) {
        boolean valido = false;
        if (null != rsaKeyLocal) {
            if(rsaKeyLocal.getKeyID().equals(keyIdRecebido)) {
                valido = true;
            }
        }
        else {
            System.out.println("RSAKey do certificado local vazio!");
        }
        return valido;
    }

    private static SignedJWT parseJoseHeader(String joseHeader) {
        SignedJWT signedJWT = null;
        try {
            if (null != joseHeader) {
                signedJWT = SignedJWT.parse(joseHeader);
            }else {
                System.out.println("Header joseHeader vazio!");
            }
        } catch (ParseException e) {
            System.out.println("Erro ao fazer parse do header para JOSEObject. " + e);
        }
        return signedJWT;
    }
}
