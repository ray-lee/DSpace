/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dspace.authenticate.factory.AuthenticateServiceFactory;
import org.dspace.authorize.AuthorizeException;
import org.dspace.content.MetadataField;
import org.dspace.content.MetadataSchema;
import org.dspace.content.MetadataSchemaEnum;
import org.dspace.content.NonUniqueMetadataException;
import org.dspace.content.factory.ContentServiceFactory;
import org.dspace.content.service.MetadataFieldService;
import org.dspace.content.service.MetadataSchemaService;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.EPersonService;
import org.dspace.eperson.service.GroupService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;

/**
 * SAML authentication for DSpace.
 *
 * @author Ray Lee
 */
public class SamlAuthentication implements AuthenticationMethod {
    private static final Logger log = LogManager.getLogger(SamlAuthentication.class);

    /**
     *
     */
    protected Map<String, String> metadataHeaderMap = null;

    /**
     * Maximum length for ePerson fields
     */
    protected final int NAME_MAX_SIZE = 64;
    protected final int PHONE_MAX_SIZE = 32;

    /**
     * Maximum length for ePerson additional metadata fields
     */
    protected final int METADATA_MAX_SIZE = 1024;

    protected EPersonService ePersonService = EPersonServiceFactory.getInstance().getEPersonService();
    protected GroupService groupService = EPersonServiceFactory.getInstance().getGroupService();
    protected MetadataFieldService metadataFieldService = ContentServiceFactory.getInstance().getMetadataFieldService();
    protected MetadataSchemaService metadataSchemaService = ContentServiceFactory.getInstance()
                                                                                 .getMetadataSchemaService();
    protected ConfigurationService configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();


    /**
     * Authenticate the given or implicit credentials. This is the heart of the
     * authentication method: test the credentials for authenticity, and if
     * accepted, attempt to match (or optionally, create) an
     * <code>EPerson</code>. If an <code>EPerson</code> is found it is set in
     * the <code>Context</code> that was passed.
     *
     * DSpace supports authentication using NetID, or email address. A user's NetID
     * is a unique identifier from the IdP that identifies a particular user. The
     * NetID can be of almost any form, such as a unique integer or string. In a
     * SAML assertion, this is known as a Name ID. There are three ways to
     * supply identity information to DSpace:
     *
     * 1) Name ID from SAML Header (best)
     *
     * The Name ID-based method is superior because users may change their email
     * address with the identity provider. When this happens DSpace will not be
     * able to associate their new address with their old account.
     *
     * 2) Email address from SAML Header (okay)
     *
     * In the case where a Name ID header is not available or not found DSpace
     * will fall back to identifying a user based-upon their email address.
     *
     * Identity Scheme Migration Strategies:
     *
     * If you are currently using Email based authentication (either 1 or 2) and
     * want to upgrade to NetID based authentication then there is an easy path.
     * Coordinate with the IdP to provide a Name ID in the SAML assertion. When a
     * user attempts to log in to DSpace first
     * DSpace will look for an EPerson with the passed Name ID, however when this
     * fails DSpace will fall back to email based authentication. Then DSpace will
     * update the user's EPerson account record to set their netid so all future
     * authentications for this user will be based upon netid. One thing to note
     * is that DSpace will prevent an account from switching NetIDs. If an account
     * already has a NetID set and then they try and authenticate with a
     * different NetID the authentication will fail.
     *
     * @param context  DSpace context, will be modified (ePerson set) upon success.
     * @param username Username (or email address) when method is explicit. Use null
     *                 for implicit method.
     * @param password Password for explicit auth, or null for implicit method.
     * @param realm    Not used by SAML-based authentication
     * @param request  The HTTP request that started this operation, or null if not
     *                 applicable.
     * @return One of: SUCCESS, NO_SUCH_USER, BAD_ARGS
     * <p>
     * Meaning: <br>
     * SUCCESS - authenticated OK. <br>
     * NO_SUCH_USER - user not found using this method. <br>
     * BAD_ARGS - user/pw not appropriate for this method
     * @throws SQLException if database error
     */
    @Override
    public int authenticate(Context context, String username, String password,
                            String realm, HttpServletRequest request) throws SQLException {

        if (request == null) {
            log.warn("Unable to authenticate using SAML because the request object is null.");

            return BAD_ARGS;
        }

        // Initialize the additional EPerson metadata.
        initialize(context);

        String nameId = findSingleAttribute(request, getNameIdAttributeName());

        if (log.isDebugEnabled()) {
            log.debug("Starting SAML Authentication");
            log.debug("Received name ID: " + nameId);
        }

        // Should we auto register new users.
        boolean autoRegister = configurationService.getBooleanProperty("authentication-saml.autoregister", true);

        // Four steps to authenticate a user
        try {
            // Step 1: Identify User
            EPerson eperson = findEPerson(context, request);

            // Step 2: Register New User, if necessary
            if (eperson == null && autoRegister) {
                eperson = registerNewEPerson(context, request);
            }

            if (eperson == null) {
                return AuthenticationMethod.NO_SUCH_USER;
            }

            // Step 3: Update User's Metadata
            updateEPerson(context, request, eperson);

            // Step 4: Log the user in.
            context.setCurrentUser(eperson);
            request.setAttribute("saml.authenticated", true);
            AuthenticateServiceFactory.getInstance().getAuthenticationService().initEPerson(context, request, eperson);

            log.info(eperson.getEmail() + " has been authenticated via SAML.");
            return AuthenticationMethod.SUCCESS;

        } catch (Throwable t) {
            // Log the error, and undo the authentication before returning a failure.
            log.error("Unable to successfully authenticate using SAML for user because of an exception.", t);
            context.setCurrentUser(null);
            return AuthenticationMethod.NO_SUCH_USER;
        }
    }

    @Override
    public List<Group> getSpecialGroups(Context context, HttpServletRequest request) throws SQLException {
        return List.of();
    }

    /**
     * Indicate whether or not a particular self-registering user can set
     * themselves a password in the profile info form.
     *
     * @param context DSpace context
     * @param request HTTP request, in case anything in that is used to decide
     * @param email   e-mail address of user attempting to register
     * @throws SQLException if database error
     */
    @Override
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request, String email) throws SQLException {
        // don't use password at all
        return false;
    }

    /**
     * Predicate, is this an implicit authentication method. An implicit method
     * gets credentials from the environment (such as an HTTP request or even
     * Java system properties) rather than the explicit username and password.
     * For example, a method that reads the X.509 certificates in an HTTPS
     * request is implicit.
     *
     * @return true if this method uses implicit authentication.
     */
    @Override
    public boolean isImplicit() {
        return false;
    }

    /**
     * Indicate whether or not a particular user can self-register, based on
     * e-mail address.
     *
     * @param context  DSpace context
     * @param request  HTTP request, in case anything in that is used to decide
     * @param username e-mail address of user attempting to register
     * @throws SQLException if database error
     */
    @Override
    public boolean canSelfRegister(Context context, HttpServletRequest request,
                                   String username) throws SQLException {

        // SAML will auto create accounts if configured to do so, but that is not
        // the same as self register. Self register means that the user can sign up for
        // an account from the web. This is not supported with SAML.
        return false;
    }

    /**
     * Initialize a new e-person record for a self-registered new user.
     *
     * @param context DSpace context
     * @param request HTTP request, in case it's needed
     * @param eperson newly created EPerson record - email + information from the
     *                registration form will have been filled out.
     * @throws SQLException if database error
     */
    @Override
    public void initEPerson(Context context, HttpServletRequest request,
                            EPerson eperson) throws SQLException {
        // We don't do anything because all our work is done in authenticate.
    }

    /**
     * Get an external login page to which to redirect. This is the URL to the authenticate
     * endpoint of a configured SAML relying party.
     *
     * @param context  DSpace context
     * @param request  The HTTP request that started this operation, or null if not
     *                 applicable.
     * @param response The HTTP response from the servlet method.
     * @return fully-qualified URL or null
     */
    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {
        String samlLoginUrl = configurationService.getProperty("authentication-saml.authenticate-endpoint");

        return response.encodeRedirectURL(samlLoginUrl);
    }

    @Override
    public String getName() {
        return "saml";
    }

    /**
     * Check if SAML plugin is enabled
     * @return true if enabled, false otherwise
     */
    public static boolean isEnabled() {
        final String samlPluginName = new SamlAuthentication().getName();
        boolean samlEnabled = false;
        // Loop through all enabled authentication plugins to see if SAML is one of them.

        Iterator<AuthenticationMethod> authenticationMethodIterator =
                AuthenticateServiceFactory.getInstance().getAuthenticationService().authenticationMethodIterator();

        while (authenticationMethodIterator.hasNext()) {
            if (samlPluginName.equals(authenticationMethodIterator.next().getName())) {
                samlEnabled = true;
                break;
            }
        }
        return samlEnabled;
    }

    /**
     * Identify an existing EPerson based upon the SAML attributes provided on
     * the request object. There are three cases where this can occur, each as
     * a fallback for the previous method.
     *
     * 1) Name ID from SAML attribute (best)
     *    The Name ID-based method is superior because users may change their email
     *    address with the identity provider. When this happens DSpace will not be
     *    able to associate their new address with their old account.
     *
     * 2) Email address from SAML attribute (okay)
     *    In the case where a Name ID header is not available or not found DSpace
     *    will fall back to identifying a user based upon their email address.
     *
     * If successful then the identified EPerson will be returned, otherwise null.
     *
     * @param context The DSpace database context
     * @param request The current HTTP Request
     * @return The EPerson identified or null.
     * @throws SQLException if database error
     * @throws AuthorizeException if authorization error
     */
    protected EPerson findEPerson(Context context, HttpServletRequest request) throws SQLException, AuthorizeException {
        String nameId = findSingleAttribute(request, getNameIdAttributeName());

        if (nameId != null) {
            EPerson ePerson = ePersonService.findByNetid(context, nameId);

            if (ePerson == null) {
                log.info("Unable to identify EPerson by netid (SAML name ID): " + nameId);
            } else {
                log.info("Identified EPerson by netid (SAML name ID): " + nameId);

                return ePerson;
            }
        }

        String emailAttributeName = getEmailAttributeName();
        String email = findSingleAttribute(request, emailAttributeName);

        if (email != null) {
            email = email.toLowerCase();

            EPerson ePerson = ePersonService.findByEmail(context, email);

            if (ePerson == null) {
                log.info("Unable to identify EPerson by email: " + emailAttributeName + "=" + email);
            } else {
                log.info("Identified EPerson by email: " + emailAttributeName + "=" + email);

                if (ePerson.getNetid() == null) {
                    return ePerson;
                }

                // The user has a netid that differs from the received SAML name ID.

                log.error("SAML authentication identified EPerson by email: " + emailAttributeName + "=" + email);
                log.error("Received SAML name ID: " + nameId);
                log.error("EPerson has netid: " + ePerson.getNetid());
                log.error(
                    "The SAML name ID is expected to be the same as the EPerson netid. " +
                    "This might be a hacking attempt to steal another user's credentials. If the " +
                    "user's netid has changed you will need to manually change it to the correct " +
                    "value or unset it in the database.");
            }
        }

        if (nameId == null && email == null) {
            log.error(
                "SAML authentication did not find a name ID or email in the request from which to indentify a user");
        }

        return null;
    }


    /**
     * Register a new eperson object. This method is called when no existing user was
     * found for the NetID or Email and autoregister is enabled. When these conditions
     * are met this method will create a new eperson object.
     *
     * In order to create a new eperson object there is a minimal set of metadata
     * required: Email, First Name, and Last Name. If we don't have access to these
     * three pieces of information then we will be unable to create a new eperson
     * object.
     *
     * Note, that this method only adds the minimal metadata. Any additional metadata
     * will need to be added by the updateEPerson method.
     *
     * @param context The current DSpace database context
     * @param request The current HTTP Request
     * @return A new eperson object or null if unable to create a new eperson.
     * @throws SQLException       if database error
     * @throws AuthorizeException if authorization error
     */
    protected EPerson registerNewEPerson(Context context, HttpServletRequest request)
        throws SQLException, AuthorizeException {

        String nameId = findSingleAttribute(request, getNameIdAttributeName());

        String emailAttributeName = getEmailAttributeName();
        String firstNameAttributeName = getFirstNameAttributeName();
        String lastNameAttributeName = getLastNameAttributeName();

        String email = findSingleAttribute(request, emailAttributeName);
        String firstName = findSingleAttribute(request, firstNameAttributeName);
        String lastName = findSingleAttribute(request, lastNameAttributeName);

        if (email == null
                || (firstNameAttributeName != null && firstName == null)
                || (lastNameAttributeName != null && lastName == null)
        ) {
            // We require that there be an email, first name, and last name. If we
            // don't have at least these three pieces of information then we fail.
            String message = "Unable to register new eperson because we are unable to find an email address along " +
                "with first and last name for the user.\n";

            message += "  name ID: " + nameId + "\n";
            message += "  email: " + emailAttributeName + "=" + email + "\n";
            message += "  first name: " + firstNameAttributeName + "=" + firstName + "\n";
            message += "  last name: " + lastNameAttributeName + "=" + lastName;

            log.error(message);

            return null;
        }

        // Truncate values of parameters that are too big.
        if (firstName != null && firstName.length() > NAME_MAX_SIZE) {
            log.warn(
                "Truncating eperson's first name because it is longer than " + NAME_MAX_SIZE + ": " + firstName);

            firstName = firstName.substring(0, NAME_MAX_SIZE);
        }
        if (lastName != null && lastName.length() > NAME_MAX_SIZE) {
            log.warn("Truncating eperson's last name because it is longer than " + NAME_MAX_SIZE + ": " + lastName);

            lastName = lastName.substring(0, NAME_MAX_SIZE);
        }

        // Turn off authorizations to create a new user
        context.turnOffAuthorisationSystem();

        EPerson ePerson = ePersonService.create(context);

        // Set the minimum attributes for the new eperson

        if (nameId != null) {
            ePerson.setNetid(nameId);
        }

        ePerson.setEmail(email.toLowerCase());

        if (firstName != null) {
            ePerson.setFirstName(context, firstName);
        }
        if (lastName != null) {
            ePerson.setLastName(context, lastName);
        }

        ePerson.setCanLogIn(true);

        // Commit the new eperson
        AuthenticateServiceFactory.getInstance().getAuthenticationService().initEPerson(context, request, ePerson);

        ePersonService.update(context, ePerson);
        context.dispatchEvents();

        // Turn authorizations back on.
        context.restoreAuthSystemState();

        if (log.isInfoEnabled()) {
            String message = "Auto registered new eperson using SAML attributes:\n";

            message += "  netid: " + ePerson.getNetid() + "\n";
            message += "  email: " + ePerson.getEmail() + "\n";
            message += "  firstName: " + ePerson.getFirstName() + "\n";
            message += "  lastName: " + ePerson.getLastName();

            log.info(message);
        }

        return ePerson;
    }


    /**
     * After we successfully authenticated a user, this method will update the user's attributes. The
     * user's email, name, or other attribute may have been changed since the last time they
     * logged into DSpace. This method will update the database with their most recent information.
     *
     * This method handles the basic DSpace metadata (email, first name, last name) along with
     * additional metadata set using the setMetadata() methods on the eperson object. The
     * additional metadata are defined by a mapping created in the dspace.cfg.
     *
     * @param context The current DSpace database context
     * @param request The current HTTP Request
     * @param eperson The eperson object to update.
     * @throws SQLException       if database error
     * @throws AuthorizeException if authorization error
     */
    protected void updateEPerson(Context context, HttpServletRequest request, EPerson eperson)
        throws SQLException, AuthorizeException {

        String nameId = findSingleAttribute(request, getNameIdAttributeName());

        String emailAttributeName = getEmailAttributeName();
        String firstNameAttributeName = getFirstNameAttributeName();
        String lastNameAttributeName = getLastNameAttributeName();

        String email = findSingleAttribute(request, emailAttributeName);
        String firstName = findSingleAttribute(request, firstNameAttributeName);
        String lastName = findSingleAttribute(request, lastNameAttributeName);

        // Truncate values of parameters that are too big.
        if (firstName != null && firstName.length() > NAME_MAX_SIZE) {
            log.warn(
                "Truncating eperson's first name because it is longer than " + NAME_MAX_SIZE + ": " + firstName);

            firstName = firstName.substring(0, NAME_MAX_SIZE);
        }

        if (lastName != null && lastName.length() > NAME_MAX_SIZE) {
            log.warn("Truncating eperson's last name because it is longer than " + NAME_MAX_SIZE + ": " + lastName);

            lastName = lastName.substring(0, NAME_MAX_SIZE);
        }

        context.turnOffAuthorisationSystem();

        // 1) Update the minimum metadata

        // Only update the netid if none has been previously set. This can occur when a repo switches
        // to netid based authentication. The current users do not have netids and fall back to email-based
        // identification but once they login we update their record and lock the account to a particular netid.
        if (nameId != null && eperson.getNetid() == null) {
            eperson.setNetid(nameId);
        }

        // The email could have changed if using netid based lookup.
        if (email != null) {
            eperson.setEmail(email.toLowerCase());
        }

        if (firstName != null) {
            eperson.setFirstName(context, firstName);
        }

        if (lastName != null) {
            eperson.setLastName(context, lastName);
        }

        if (log.isDebugEnabled()) {
            String message = "Updated the eperson's minimal metadata: \n";

            message += " Email: " + emailAttributeName + "=" + email + "' \n";
            message += " First Name: " + firstNameAttributeName +  "=" + firstName + "\n";
            message += " Last Name: " + lastNameAttributeName + "=" + lastName;

            log.debug(message);
        }

        // 2) Update additional eperson metadata
        for (String attributeName : metadataHeaderMap.keySet()) {

            String metadataFieldName = metadataHeaderMap.get(attributeName);
            String value = findSingleAttribute(request, attributeName);

            // Truncate values
            if (value == null) {
                log.warn("Unable to update the eperson's '{}' metadata"
                        + " because the attribute '{}' does not exist.", metadataFieldName, attributeName);
                continue;
            } else if ("phone".equals(metadataFieldName) && value.length() > PHONE_MAX_SIZE) {
                log.warn("Truncating eperson phone metadata because it is longer than {}: {}",
                        PHONE_MAX_SIZE, value);
                value = value.substring(0, PHONE_MAX_SIZE);
            } else if (value.length() > METADATA_MAX_SIZE) {
                log.warn("Truncating eperson {} metadata because it is longer than {}: {}",
                        metadataFieldName, METADATA_MAX_SIZE, value);
                value = value.substring(0, METADATA_MAX_SIZE);
            }

            ePersonService.setMetadataSingleValue(context, eperson,
                    MetadataSchemaEnum.EPERSON.getName(), metadataFieldName, null, null, value);
            log.debug("Updated the eperson's {} metadata using attribute: {}={}",
                    metadataFieldName, attributeName, value);
        }
        ePersonService.update(context, eperson);
        context.dispatchEvents();
        context.restoreAuthSystemState();
    }

    /**
     * Initialize SAML Authentication.
     *
     * During initalization the mapping of additional eperson metadata will be loaded from the DSpace.cfg
     * and cached. While loading the metadata mapping this method will check the EPerson object to see
     * if it supports the metadata field. If the field is not supported and autocreate is turned on then
     * the field will be automatically created.
     *
     * It is safe to call this methods multiple times.
     *
     * @param context context
     * @throws SQLException if database error
     */
    protected synchronized void initialize(Context context) throws SQLException {

        if (metadataHeaderMap != null) {
            return;
        }

        HashMap<String, String> map = new HashMap<>();

        String[] mappingString = configurationService.getArrayProperty("authentication-saml.eperson.metadata");

        boolean autoCreate = configurationService
            .getBooleanProperty("authentication-saml.eperson.metadata.autocreate", true);

        // Bail out if not set, returning an empty map.
        if (mappingString == null || mappingString.length == 0) {
            log.debug("No additional eperson metadata mapping found: authentication-saml.eperson.metadata");

            metadataHeaderMap = map;
            return;
        }

        log.debug("Loading additional eperson metadata from: authentication-saml.eperson.metadata="
            + StringUtils.join(mappingString, ","));

        for (String metadataString : mappingString) {
            metadataString = metadataString.trim();

            String[] metadataParts = metadataString.split("=>");

            if (metadataParts.length != 2) {
                log.error("Unable to parse metadat mapping string: '" + metadataString + "'");
                continue;
            }

            String attributeName = metadataParts[0].trim();
            String metadataFieldName = metadataParts[1].trim().toLowerCase();

            boolean valid = checkIfEpersonMetadataFieldExists(context, metadataFieldName);

            if (!valid && autoCreate) {
                valid = autoCreateEpersonMetadataField(context, metadataFieldName);
            }

            if (valid) {
                // The eperson field is fine, we can use it.
                log.debug("Loading additional eperson metadata mapping for: {}={}",
                        attributeName, metadataFieldName);
                map.put(attributeName, metadataFieldName);
            } else {
                // The field doesn't exist, and we can't use it.
                log.error("Skipping the additional eperson metadata mapping for: {}={}"
                        + " because the field is not supported by the current configuration.",
                        attributeName, metadataFieldName);
            }
        } // foreach metadataStringList

        metadataHeaderMap = map;
    }

    /**
     * Check if a MetadataField for an eperson is available.
     *
     * @param metadataName The name of the metadata field.
     * @param context      context
     * @return True if a valid metadata field, otherwise false.
     * @throws SQLException if database error
     */
    protected synchronized boolean checkIfEpersonMetadataFieldExists(Context context, String metadataName)
        throws SQLException {

        if (metadataName == null) {
            return false;
        }

        MetadataField metadataField = metadataFieldService.findByElement(context,
                MetadataSchemaEnum.EPERSON.getName(), metadataName, null);
        return metadataField != null;
    }

    /**
     * Validate Postgres Column Names
     */
    protected final String COLUMN_NAME_REGEX = "^[_A-Za-z0-9]+$";

    /**
     * Automatically create a new metadataField for an eperson
     *
     * @param context      context
     * @param metadataName The name of the new metadata field.
     * @return True if successful, otherwise false.
     * @throws SQLException if database error
     */
    protected synchronized boolean autoCreateEpersonMetadataField(Context context, String metadataName)
        throws SQLException {

        if (metadataName == null) {
            return false;
        }

        // The phone is a predefined field
        if ("phone".equals(metadataName)) {
            return true;
        }

        if (!metadataName.matches(COLUMN_NAME_REGEX)) {
            return false;
        }

        MetadataSchema epersonSchema = metadataSchemaService.find(context, "eperson");
        MetadataField metadataField = null;
        try {
            context.turnOffAuthorisationSystem();
            metadataField = metadataFieldService.create(context, epersonSchema, metadataName, null, null);
        } catch (AuthorizeException | NonUniqueMetadataException e) {
            log.error(e.getMessage(), e);
            return false;
        } finally {
            context.restoreAuthSystemState();
        }
        return metadataField != null;
    }

    @Override
    public boolean isUsed(final Context context, final HttpServletRequest request) {
        if (request != null &&
                context.getCurrentUser() != null &&
                request.getAttribute("saml.authenticated") != null) {
            return true;
        }
        return false;
    }

    @Override
    public boolean canChangePassword(Context context, EPerson ePerson, String currentPassword) {
        return false;
    }

    private String findSingleAttribute(HttpServletRequest request, String name) {
        if (StringUtils.isBlank(name)) {
            return null;
        }

        Object value = request.getAttribute(name);

        if (value instanceof List) {
            List<?> list = (List<?>) value;

            if (list.size() == 0) {
                value = null;
            } else {
                value = list.get(0);
            }
        }

        return (value == null ? null : value.toString());
    }

    private String getNameIdAttributeName() {
        return configurationService.getProperty("authentication-saml.attribute.name-id");
    }

    private String getEmailAttributeName() {
        return configurationService.getProperty("authentication-saml.attribute.email");
    }

    private String getFirstNameAttributeName() {
        return configurationService.getProperty("authentication-saml.attribute.first-name");
    }

    private String getLastNameAttributeName() {
        return configurationService.getProperty("authentication-saml.attribute.last-name");
    }
}
