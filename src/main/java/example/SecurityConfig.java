package example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // This will enable the metadata endpoint
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
                new DefaultRelyingPartyRegistrationResolver(this.relyingPartyRegistrationRepository);

        Saml2MetadataFilter filter = new Saml2MetadataFilter(
                relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());

        // Add the filter before the SAML filter
        http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);

        // Allow access to login and processing endpoints - without context path
        http
                .authorizeRequests()
                .antMatchers("/login", "/process-email", "/css/**", "/js/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf()
                .ignoringAntMatchers("/process-email");

        // Configure custom entry point to redirect to our login page
        http
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));

        // Configure SAML2 login using default configuration
        http.saml2Login(Customizer.withDefaults());
    }
}