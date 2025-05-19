package com.verint.springsaml.authenticator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collection;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    // @Value("${saml.v2.metadata-location}")
    //  private String metadataLocation;

    @Value("${saml.azure.metadata-url}")
    private String metadataUrl;

    @Value("${saml.azure.entity-id}")
    private String entityId;

    @Value("${saml.azure.assertionConsumerServiceLocation}")
    private String assertionConsumerServiceLocation;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        System.out.println("BENJAMIN Creating RelyingPartyRegistrationRepository" + metadataUrl);

        String registrationID = "azure";
        System.out.println("BENJAMIN assertionConsumerServiceLocation = " + assertionConsumerServiceLocation + registrationID);

        try {

            RelyingPartyRegistration registration =
                    RelyingPartyRegistrations
                            .fromMetadataLocation(metadataUrl)
                            .registrationId(registrationID)
                            .entityId(entityId) // for azure
                            .assertionConsumerServiceLocation(assertionConsumerServiceLocation + registrationID) // tell IdP to send response to here
                            .build();


            Collection<Saml2X509Credential> verificationCredentials = registration.getAssertingPartyDetails().getVerificationX509Credentials();
            if (verificationCredentials.isEmpty()) {
                System.out.println("BENJAMIN vefifyMetadataLoading: verification credentials not found");
            } else {
                Saml2X509Credential firstCert = verificationCredentials.iterator().next();
                X509Certificate cert = firstCert.getCertificate();
                System.out.println("BENJAMIN cert.getSubjectX500Principal().getName() " + cert.getSubjectX500Principal().getName());
                System.out.println("BENJAMIN cert.getIssuerX500Principal().getName() " + cert.getIssuerX500Principal().getName());
            }
            return new InMemoryRelyingPartyRegistrationRepository(registration);

        } catch (Exception e) {
            System.out.println("BENJAMIN Creating RelyingPartyRegistrationRepository" + e);
            return new InMemoryRelyingPartyRegistrationRepository();
        }

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("BENJAMIN Creating samlSecurityFilterChain");
        //System.err.println("BENJAMIN Creating samlSecurityFilterChain");
        // This will enable the metadata endpoint
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository());

        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

        // Add the filter before the SAML filter
        http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);

        // Allow access to login and processing endpoints - without context path
        http
                .authorizeRequests()
                .antMatchers("/login", "/process-email", "success", "/css/**", "/js/**").permitAll()
                .antMatchers("/saml2/authenticate/**").permitAll()
                .anyRequest().authenticated();
        http.csrf()
                .ignoringAntMatchers("/process-email");

        // Configure custom entry point to redirect to our login page
        http
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));

        //set success handler
        http.saml2Login(saml2 -> saml2
                .loginProcessingUrl("/saml2/acs/{registrationId}") //setting this is a must for a custom ACS url
                .successHandler(successHandler())
        );
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/success");
        return successHandler;
    }
}