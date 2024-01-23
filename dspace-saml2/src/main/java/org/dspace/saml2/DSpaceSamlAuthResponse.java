/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.saml2;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * A response wrapper for SAML authentication requests that are forwarded to the DSpace
 * authentication endpoint from the assertion consumer endpoint of the SAML relying party.
 * <p>
 * This ignores attempts to set the DSpace XSRF header/cookie, so that neither are sent to the
 * browser following a successful SAML authentication. In a SAML login flow, the asserting party
 * redirects the browser to the relying party's assertion consumer ndpoint following a successful
 * login. The assertion consumer then forwards the request to the DSpace SAML authentication
 * endpoint. This means that the request to the authentication endpoint originated from the browser
 * itself, not a JavaScript agent running in the browser, and there is nothing to handle a received
 * DSPACE-XSRF-TOKEN header in the response. The token and cookie would then be out of sync on the
 * next request sent from the JavaScript agent on on the browser.
 * </p>
 *
 * @author Ray Lee
 */
public class DSpaceSamlAuthResponse extends HttpServletResponseWrapper {
    public DSpaceSamlAuthResponse(HttpServletResponse response) {
        super(response);
    }

    /**
     * Blocks attempts to add the DSpace XSRF token and cookie headers. Attempts to add other
     * headers are passed through to the wrapped request.
     */
    @Override
    public void addHeader(String name, String value) {
        if (!shouldIgnoreHeader(name, value)) {
            super.addHeader(name, value);
        }
    }

    /**
     * Blocks attempts to set the DSpace XSRF token and cookie headers. Attempts to set other
     * headers are passed through to the wrapped request.
     */
    @Override
    public void setHeader(String name, String value) {
        if (!shouldIgnoreHeader(name, value)) {
            super.setHeader(name, value);
        }
    }

    private boolean shouldIgnoreHeader(String name, String value) {
        if (name.equalsIgnoreCase("DSPACE-XSRF-TOKEN")) {
            return true;
        }

        if (name.equalsIgnoreCase("Set-cookie") && value.startsWith("DSPACE-XSRF-COOKIE")) {
            return true;
        }

        return false;
    }
}
