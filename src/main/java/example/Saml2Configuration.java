package example;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;

/**
 * Spring Boot configuration that provides our custom factory as the primary bean
 * This will replace the default factory in the Spring application context
 */
@Configuration
public class Saml2Configuration {

    /**
     * Create our custom SAML authentication request factory as the primary bean
     * This will be used instead of the default OpenSamlAuthenticationRequestFactory
     */
    @Bean
    @Primary
    //@ConditionalOnMissingBean(Saml2AuthenticationRequestFactory.class)
    public Saml2AuthenticationRequestFactory saml2AuthenticationRequestFactory() {
        return new VerintLoginHintAuthenticationRequestFactory();
    }
}