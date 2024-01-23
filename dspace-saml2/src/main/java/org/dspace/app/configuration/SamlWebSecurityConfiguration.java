/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.configuration;

import org.dspace.saml2.DSpaceSamlAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Web security configuration for SAML relying party endpoints.
 * <p>
 * This establishes and manages security for the following endpoints:
 * <ul>
 *   <li>/saml2/service-provider-metadata/{relyingPartyRegistrationId}</li>
 *   <li>/saml2/authenticate/{relyingPartyRegistrationId}</li>
 *   <li>/saml2/assertion-consumer/{relyingPartyRegistrationId}</li>
 * </ul>
 * </p>
 * <p>
 * This @Configuration class is automatically discovered by Spring Boot via a @ComponentScan
 * on the org.dspace.app.configuration package.
 * <p>
 *
 * @author Ray Lee
 */
@EnableWebSecurity
@Configuration
@ComponentScan(basePackages = "org.dspace.saml2")
public class SamlWebSecurityConfiguration {
    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Bean
    public SecurityFilterChain samlSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .requestMatchers()
                .antMatchers("/saml2/**")
            .and()
            .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/saml2/service-provider-metadata/**").permitAll()
            .and()
            // Initiate SAML login at /saml2/authenticate/{registrationId}.
            .saml2Login()
                .loginProcessingUrl("/saml2/assertion-consumer/{registrationId}")
                .successHandler(new DSpaceSamlAuthenticationSuccessHandler())
            .and()
            // Produce relying party metadata at /saml2/service-provider-metadata/{registrationId}.
            .addFilterBefore(
                new Saml2MetadataFilter(
                    (RelyingPartyRegistrationResolver)
                        new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository),
                    new OpenSamlMetadataResolver()
                ),
                Saml2WebSsoAuthenticationFilter.class
            )
            .build();
    }
}
