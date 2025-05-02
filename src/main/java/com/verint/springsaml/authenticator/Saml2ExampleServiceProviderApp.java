package com.verint.springsaml.authenticator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class Saml2ExampleServiceProviderApp extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application){
        return application.sources(Saml2ExampleServiceProviderApp.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(Saml2ExampleServiceProviderApp.class, args);
    }
}
