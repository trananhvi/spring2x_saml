package example;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;

import javax.xml.namespace.QName;

/**
 * Custom SAML Authentication Request Factory that adds Okta-specific login_hint
 * as a query parameter and/or extension to the SAML AuthnRequest
 */
public class OktaLoginHintAuthenticationRequestFactory extends OpenSamlAuthenticationRequestFactory {

    private static final String HARDCODED_EMAIL = "hardcoded.user@example.com";

    public OktaLoginHintAuthenticationRequestFactory() {
        super();
        // Override the default converter to use our custom converter that adds login_hint
        setAuthenticationRequestContextConverter(new OktaLoginHintAuthnRequestConverter());
    }

    /**
     * Override the redirect authentication request creation to add login_hint
     * to the destination URL in addition to any extensions
     */
    @Override
    public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(
            Saml2AuthenticationRequestContext context) {
        // Let the superclass create the basic request first
        Saml2RedirectAuthenticationRequest request = super.createRedirectAuthenticationRequest(context);

        // Get the destination URL and add login_hint parameter
        String destination = request.getAuthenticationRequestUri();
        if (destination != null) {
            String modifiedDestination;
            if (destination.contains("?")) {
                modifiedDestination = destination + "&login_hint=" + HARDCODED_EMAIL;
            } else {
                modifiedDestination = destination + "?login_hint=" + HARDCODED_EMAIL;
            }

            // Create a new builder with the modified destination
            Saml2RedirectAuthenticationRequest.Builder builder = Saml2RedirectAuthenticationRequest
                    .withAuthenticationRequestContext(context)
                    .samlRequest(request.getSamlRequest())
                    .relayState(request.getRelayState())
                    .authenticationRequestUri(modifiedDestination);

            // Add signature parameters if present
            if (request.getSignature() != null) {
                builder.signature(request.getSignature());
            }
            if (request.getSigAlg() != null) {
                builder.sigAlg(request.getSigAlg());
            }

            return builder.build();
        }

        return request;
    }

    /**
     * Override the post authentication request creation (if needed)
     * The login_hint extension will already be added by our converter
     */
    @Override
    public Saml2PostAuthenticationRequest createPostAuthenticationRequest(
            Saml2AuthenticationRequestContext context) {
        return super.createPostAuthenticationRequest(context);
    }

    /**
     * Custom converter that adds Okta login_hint extension to the SAML AuthnRequest
     */
    private class OktaLoginHintAuthnRequestConverter implements Converter<Saml2AuthenticationRequestContext, AuthnRequest> {

        @Override
        public AuthnRequest convert(Saml2AuthenticationRequestContext context) {
            // First, let the default factory create a basic AuthnRequest
            AuthnRequest authnRequest = createDefaultAuthnRequest(context);

            try {
                // Add login_hint as extension element
                if (authnRequest.getExtensions() == null) {
                    ExtensionsBuilder extensionsBuilder = new ExtensionsBuilder();
                    Extensions extensions = extensionsBuilder.buildObject();
                    authnRequest.setExtensions(extensions);
                }

                // Create login_hint extension element with Okta's namespace
                QName loginHintQName = new QName("http://schemas.okta.com/extensions/authnrequest", "loginHint", "okta");
                XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(XSString.TYPE_NAME);
                XSString loginHint = stringBuilder.buildObject(loginHintQName, XSString.TYPE_NAME);
                loginHint.setValue(HARDCODED_EMAIL);

                // Add the extension to the AuthnRequest
                authnRequest.getExtensions().getUnknownXMLObjects().add(loginHint);

                // Modify destination to include login_hint query parameter (redundant but ensures it gets through)
                String destination = authnRequest.getDestination();
                if (destination != null) {
                    if (destination.contains("?")) {
                        authnRequest.setDestination(destination + "&login_hint=" + HARDCODED_EMAIL);
                    } else {
                        authnRequest.setDestination(destination + "?login_hint=" + HARDCODED_EMAIL);
                    }
                }
            } catch (Exception e) {
                System.err.println("Error adding login_hint to SAML request: " + e.getMessage());
            }

            return authnRequest;
        }

        /**
         * Helper to create a default AuthnRequest
         * We need this intermediary method because the OpenSamlAuthenticationRequestFactory's
         * createAuthnRequest method is private, so we use the converter mechanism instead
         */
        private AuthnRequest createDefaultAuthnRequest(Saml2AuthenticationRequestContext context) {
            // Create a temporary instance of OpenSamlAuthenticationRequestFactory
            OpenSamlAuthenticationRequestFactory factory = new OpenSamlAuthenticationRequestFactory();

            // Here's the tricky part - we need to get the default converter
            // We're using a small trick to get the AuthnRequest object generated by the default factory
            final AuthnRequest[] authnRequestHolder = new AuthnRequest[1];

            // Create a custom converter that will capture the AuthnRequest created by the default factory
            Converter<Saml2AuthenticationRequestContext, AuthnRequest> captureConverter =
                    new Converter<Saml2AuthenticationRequestContext, AuthnRequest>() {
                        @Override
                        public AuthnRequest convert(Saml2AuthenticationRequestContext ctx) {
                            // Store the reference to be returned later
                            // We can't directly access the result, but it will be used internally by the factory
                            return authnRequestHolder[0];
                        }
                    };

            // Now we need to use reflection to get the original converter from the new factory
            try {
                java.lang.reflect.Field converterField = OpenSamlAuthenticationRequestFactory.class
                        .getDeclaredField("authenticationRequestContextConverter");
                converterField.setAccessible(true);

                // Get the default converter
                @SuppressWarnings("unchecked")
                Converter<Saml2AuthenticationRequestContext, AuthnRequest> defaultConverter =
                        (Converter<Saml2AuthenticationRequestContext, AuthnRequest>) converterField.get(factory);

                // Use the default converter to create the AuthnRequest
                authnRequestHolder[0] = defaultConverter.convert(context);

                // Return the created AuthnRequest
                return authnRequestHolder[0];
            } catch (Exception e) {
                throw new RuntimeException("Failed to create default AuthnRequest", e);
            }
        }
    }
}