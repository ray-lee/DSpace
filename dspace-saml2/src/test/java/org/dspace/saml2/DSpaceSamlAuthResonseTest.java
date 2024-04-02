/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.saml2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

public class DSpaceSamlAuthResonseTest {
    @Test
    public void testSetTokenHeader() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.setHeader("DSPACE-XSRF-TOKEN", "value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("DSPACE-XSRF-TOKEN"));
        assertFalse(samlAuthResponse.containsHeader("DSPACE-XSRF-TOKEN"));
        assertNull(samlAuthResponse.getHeader("DSPACE-XSRF-TOKEN"));
    }

    @Test
    public void testSetTokenHeaderLowercase() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.setHeader("dspace-xsrf-token", "value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("dspace-xsrf-token"));
        assertFalse(samlAuthResponse.containsHeader("dspace-xsrf-token"));
        assertNull(samlAuthResponse.getHeader("dspace-xsrf-token"));
    }

    @Test
    public void testAddTokenHeader() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.addHeader("DSPACE-XSRF-TOKEN", "value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("DSPACE-XSRF-TOKEN"));
        assertFalse(samlAuthResponse.containsHeader("DSPACE-XSRF-TOKEN"));
        assertNull(samlAuthResponse.getHeader("DSPACE-XSRF-TOKEN"));
    }

    @Test
    public void testAddTokenHeaderLowercase() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.addHeader("dspace-xsrf-token", "value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("dspace-xsrf-token"));
        assertFalse(samlAuthResponse.containsHeader("dspace-xsrf-token"));
        assertNull(samlAuthResponse.getHeader("dspace-xsrf-token"));
    }

    @Test
    public void testSetCookieHeader() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.setHeader("Set-cookie", "DSPACE-XSRF-COOKIE=value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("Set-cookie"));
        assertFalse(samlAuthResponse.containsHeader("Set-cookie"));
        assertNull(samlAuthResponse.getHeader("Set-cookie"));
    }

    @Test
    public void testSetCookieHeaderLowercase() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.setHeader("set-cookie", "dspace-xsrf-cookie=value");

        assertFalse(samlAuthResponse.getHeaderNames().contains("set-cookie"));
        assertFalse(samlAuthResponse.containsHeader("set-cookie"));
        assertNull(samlAuthResponse.getHeader("set-cookie"));
    }

    @Test
    public void testAddCookieHeader() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.addHeader("Set-cookie", "DSPACE-XSRF-COOKIE=value");
        samlAuthResponse.addHeader("Set-cookie", "SOMETHING-ELSE=another value");

        assertTrue(samlAuthResponse.getHeaderNames().contains("Set-cookie"));
        assertTrue(samlAuthResponse.containsHeader("Set-cookie"));
        assertEquals(1, samlAuthResponse.getHeaders("Set-cookie").size());
        assertEquals("SOMETHING-ELSE=another value", samlAuthResponse.getHeader("Set-cookie"));
    }

    @Test
    public void testAddCookieHeaderLowercase() throws Exception {
        DSpaceSamlAuthResponse samlAuthResponse = new DSpaceSamlAuthResponse(new MockHttpServletResponse());

        samlAuthResponse.addHeader("set-cookie", "dspace-xsrf-cookie=value");
        samlAuthResponse.addHeader("Set-cookie", "SOMETHING-ELSE=another value");

        assertTrue(samlAuthResponse.getHeaderNames().contains("set-cookie"));
        assertTrue(samlAuthResponse.containsHeader("set-cookie"));
        assertEquals(1, samlAuthResponse.getHeaders("set-cookie").size());
        assertEquals("SOMETHING-ELSE=another value", samlAuthResponse.getHeader("set-cookie"));
    }
}
