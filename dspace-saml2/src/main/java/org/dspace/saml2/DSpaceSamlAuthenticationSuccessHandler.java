/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.saml2;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Success handler for SAML authentication.
 * <p>
 * When a SAML authentication succeeds:
 * </p>
 * <ul>
 *   <li>Extract attributes from the assertion, and map them into request attributes using the mapping
 *       configured in saml-relying-party.cfg for the relying party that initiated the login.</li>
 *   <li>Forward the request to the DSpace SAML authentication endpoint.</li>
 * </ul>
 *
 * @author Ray Lee
 */
public class DSpaceSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(DSpaceSamlAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        String relyingPartyId = principal.getRelyingPartyRegistrationId();
        Map<String, List<Object>> samlAttributes = principal.getAttributes();

        setRequestAttributesFromSamlAttributes(request, relyingPartyId, samlAttributes);

        request.setAttribute("org.dspace.saml.RELYING_PARTY_ID", relyingPartyId);
        request.setAttribute("org.dspace.saml.NAME_ID", principal.getName());
        request.setAttribute("org.dspace.saml.ATTRIBUTES", samlAttributes);

        request.getRequestDispatcher("/api/authn/saml")
            .forward(new DSpaceSamlAuthRequest(request), new DSpaceSamlAuthResponse(response));
    }

    private void setRequestAttributesFromSamlAttributes(
        HttpServletRequest request, String relyingPartyId, Map<String, List<Object>> samlAttributes
    ) {
        ConfigurationService configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();

        String[] attributeMappings = configurationService.getArrayProperty(
            "saml-relying-party." + relyingPartyId + ".attributes");

        if (attributeMappings == null || attributeMappings.length == 0) {
            logger.warn("No SAML attribute mappings found for relying party {}", relyingPartyId);

            return;
        }

        Arrays.stream(attributeMappings)
            .forEach(attributeMapping -> {
                String[] parts = attributeMapping.split("=>");

                if (parts.length != 2) {
                    logger.error("Unable to parse SAML attribute mapping for relying party {}: {}",
                        relyingPartyId, attributeMapping);

                    return;
                }

                String samlAttributeName = parts[0].trim();
                String requestAttributeName = parts[1].trim();

                List<Object> values = samlAttributes.get(samlAttributeName);

                if (values != null) {
                    request.setAttribute(requestAttributeName, values);
                }
            });
    }
}
