package br.com.t3privacyguard.security;

import br.com.t3privacyguard.integration.GatewayRemediationClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("test")
public class RemediationAuthorizationTestConfiguration {
    @Bean
    RemediationAuthorizationSigner remediationAuthorizationSigner(ObjectMapper mapper, GatewayRemediationClient gateway) throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encodedPublic = keys.getPublic().getEncoded();
        String publicKeyHex = HexFormat.of().formatHex(Arrays.copyOfRange(encodedPublic, encodedPublic.length - 32, encodedPublic.length));
        String privateKey = Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded());
        return new RemediationAuthorizationSigner(mapper, privateKey, publicKeyHex, "test-v2", 60, gateway::requireExecutorDid);
    }
}
