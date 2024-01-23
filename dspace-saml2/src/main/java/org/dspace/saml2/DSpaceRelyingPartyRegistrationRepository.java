/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.saml2;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.io.CharStreams;
import org.apache.commons.configuration2.HierarchicalConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationRuntimeException;
import org.apache.commons.configuration2.tree.ImmutableNode;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Component;

/**
 * A SAML RelyingPartyRegistrationRepository that builds and stores relying parties from a DSpace
 * configuration file, saml-relying-party.cfg.
 *
 * @author Ray Lee
 */
@Component
public class DSpaceRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {
    private static final Logger logger = LoggerFactory.getLogger(DSpaceRelyingPartyRegistrationRepository.class);

    private RelyingPartyRegistrationRepository repository = null;

    public DSpaceRelyingPartyRegistrationRepository() {
        ConfigurationService configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();

        List<RelyingPartyRegistration> registrations = configurationService.getChildren("saml-relying-party").stream()
            .map(relyingPartyConfiguration -> buildRelyingPartyRegistration(relyingPartyConfiguration))
            .filter(registration -> registration != null)
            .collect(Collectors.toList());

        if (registrations.size() > 0) {
            this.repository = new InMemoryRelyingPartyRegistrationRepository(registrations);
        }
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        if (this.repository == null) {
            return null;
        }

        return this.repository.findByRegistrationId(registrationId);
    }

    public RelyingPartyRegistration buildRelyingPartyRegistration(
        HierarchicalConfiguration<ImmutableNode> configuration
    ) {
        String relyingPartyId = configuration.getRootElementName();

        try {
            HierarchicalConfiguration<ImmutableNode> assertingPartyConfiguration =
                getConfigurationAt(configuration, "asserting-party");

            if (assertingPartyConfiguration == null) {
                logger.warn("Couldn't find SAML asserting-party configuration for relying-party {}. "
                    + "Relying party will not be registered.", relyingPartyId);

                return null;
            }

            String metadataUri = assertingPartyConfiguration.getString("metadata-uri");
            RelyingPartyRegistration.Builder registrationBuilder;

            if (metadataUri != null) {
                registrationBuilder = RelyingPartyRegistrations
                    .fromMetadataLocation(metadataUri)
                    .registrationId(relyingPartyId);
            } else {
                registrationBuilder = RelyingPartyRegistration
                    .withRegistrationId(relyingPartyId);
            }

            registrationBuilder.assertionConsumerServiceLocation("{baseUrl}/saml2/assertion-consumer/{registrationId}");

            registrationBuilder.assertingPartyDetails(assertingParty -> {
                String entityId = assertingPartyConfiguration.getString("entity-id");

                if (entityId != null) {
                    assertingParty.entityId(entityId);
                }

                HierarchicalConfiguration<ImmutableNode> ssoConfiguration =
                    getConfigurationAt(assertingPartyConfiguration, "single-sign-on");

                if (ssoConfiguration != null) {
                    String url = ssoConfiguration.getString("url");

                    if (url != null) {
                        assertingParty.singleSignOnServiceLocation(url);
                    }

                    String binding = ssoConfiguration.getString("binding");

                    if (binding != null) {
                        assertingParty.singleSignOnServiceBinding(Saml2MessageBinding.valueOf(binding.toUpperCase()));
                    }

                    Boolean shouldSignRequest = ssoConfiguration.getBoolean("sign-request");

                    if (shouldSignRequest != null) {
                        assertingParty.wantAuthnRequestsSigned(shouldSignRequest);
                    }
                }

                HierarchicalConfiguration<ImmutableNode> sloConfiguration =
                    getConfigurationAt(assertingPartyConfiguration, "single-logout");

                if (sloConfiguration != null) {
                    String url = sloConfiguration.getString("url");

                    if (url != null) {
                        assertingParty.singleLogoutServiceLocation(url);
                    }

                    String binding = sloConfiguration.getString("binding");

                    if (binding != null) {
                        assertingParty.singleLogoutServiceBinding(Saml2MessageBinding.valueOf(binding.toUpperCase()));
                    }

                    String responseUrl = sloConfiguration.getString("response-url");

                    if (responseUrl != null) {
                        assertingParty.singleLogoutServiceResponseLocation(responseUrl);
                    }
                }

                assertingPartyConfiguration.childConfigurationsAt("verification.credentials").stream()
                    .forEach(credentialsConfiguration -> {
                        String certificateLocation = credentialsConfiguration.getString("certificate-location");

                        if (certificateLocation != null) {
                            X509Certificate certificate = certificateFromUrl(certificateLocation);

                            if (certificate != null) {
                                assertingParty.verificationX509Credentials(credentials ->
                                    credentials.add(Saml2X509Credential.verification(certificate)));
                            }
                        }
                    });
            });

            configuration.childConfigurationsAt("signing.credentials").stream()
                .forEach(credentialsConfiguration -> {
                    String privateKeyLocation = credentialsConfiguration.getString("private-key-location");
                    String certificateLocation = credentialsConfiguration.getString("certificate-location");

                    PrivateKey privateKey = privateKeyFromUrl(privateKeyLocation);
                    X509Certificate certificate = certificateFromUrl(certificateLocation);

                    if (privateKey != null && certificate != null) {
                        registrationBuilder.signingX509Credentials(credentials ->
                            credentials.add(Saml2X509Credential.signing(privateKey, certificate)));
                    }
                });

            configuration.childConfigurationsAt("decryption.credentials").stream()
                .forEach(credentialsConfiguration -> {
                    String privateKeyLocation = credentialsConfiguration.getString("private-key-location");
                    String certificateLocation = credentialsConfiguration.getString("certificate-location");

                    PrivateKey privateKey = privateKeyFromUrl(privateKeyLocation);
                    X509Certificate certificate = certificateFromUrl(certificateLocation);

                    if (privateKey != null && certificate != null) {
                        registrationBuilder.decryptionX509Credentials(credentials ->
                            credentials.add(Saml2X509Credential.decryption(privateKey, certificate)));
                    }
                });

            return registrationBuilder.build();
        } catch (Exception e) {
            logger.error("Error building SAML relying party registration for id " + relyingPartyId, e);

            return null;
        }
    }

    private HierarchicalConfiguration<ImmutableNode> getConfigurationAt(
        HierarchicalConfiguration<ImmutableNode> configuration, String key
    ) {
        try {
            return configuration.configurationAt(key);
        } catch (ConfigurationRuntimeException e) {
            return null;
        }
    }

    /**
     * Reads and decodes a private key from a given URL. The URL must point to a PEM file
     * containing a PKCS8-encoded private key.
     *
     * @see <a href="https://www.baeldung.com/java-read-pem-file-keys">Baeldung</a>
     *
     * @param url The URL where the PRM file is located. This can be a file:// URL.
     * @return The private key.
     */
    private PrivateKey privateKeyFromUrl(String url) {
        if (url == null || url.length() == 0) {
            return null;
        }

        Resource resource;

        try {
            resource = new UrlResource(url);
        } catch (MalformedURLException ex) {
            logger.error("Malformed private key url: " + url);

            return null;
        }

        if (!resource.exists()) {
            logger.error("No resource exists at private key url: " + url);

            return null;
        }

        try (Reader reader = new InputStreamReader(resource.getInputStream())) {
            String key = CharStreams.toString(reader);

            String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception ex) {
            logger.error("Error reading private key from " + url, ex);

            return null;
        }
    }

    /**
     * Reads an X509 certificate from a given URL.
     *
     * @param url The URL where the certificate is located. This can be a file:// URL.
     * @return The X509 certificate.
     */
    private X509Certificate certificateFromUrl(String url) {
        if (url == null || url.length() == 0) {
            return null;
        }

        Resource resource;

        try {
            resource = new UrlResource(url);
        } catch (MalformedURLException ex) {
            logger.error("Malformed certificate url: " + url);

            return null;
        }

        if (!resource.exists()) {
            logger.error("No resource exists at certificate url: " + url);

            return null;
        }

        try (InputStream is = resource.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        } catch (Exception ex) {
            logger.error("Error reading certificate from " + url, ex);

            return null;
        }
    }
}
