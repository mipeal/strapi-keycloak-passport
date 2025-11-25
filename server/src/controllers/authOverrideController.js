'use strict';

import axios from 'axios';
import crypto from 'crypto';

/**
 * Generates a cryptographically secure random state for CSRF protection.
 *
 * @function generateState
 * @returns {string} A random state string.
 */
function generateState() {
  return crypto.randomUUID();
}

/**
 * Builds the Keycloak authorization URL.
 *
 * @function buildAuthorizationUrl
 * @param {Object} config - Plugin configuration.
 * @param {string} redirectUri - The redirect URI.
 * @param {string} state - The CSRF state parameter.
 * @returns {URL} The Keycloak authorization URL.
 */
function buildAuthorizationUrl(config, redirectUri, state) {
  const authUrl = new URL(`${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/auth`);
  authUrl.searchParams.set('client_id', config.KEYCLOAK_CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', state);
  return authUrl;
}

/**
 * @module AuthOverrideController
 * @description Handles Keycloak authentication and synchronizes users with Strapi.
 * Supports both legacy password grant (Keycloak < 18) and Authorization Code flow (Keycloak 18+).
 */
export default {
  /**
   * Handles Keycloak login and synchronizes the user with Strapi.
   * This method uses the password grant type (deprecated in Keycloak 18+).
   * For Keycloak 18+, use the OAuth2 Authorization Code flow via /authorize endpoint.
   *
   * @async
   * @function login
   * @param {Object} ctx - Koa context.
   * @param {Object} ctx.request - Request object containing body data.
   * @param {Object} ctx.request.body - Request body data.
   * @param {string} ctx.request.body.email - The email address of the user attempting to log in.
   * @param {string} ctx.request.body.password - The password of the user attempting to log in.
   * @returns {Promise<Object>} The response containing JWT and user details.
   * @throws {Error} If authentication fails or credentials are invalid.
   */
  async login(ctx) {
    try {
      /** @type {string} */
      const email = ctx.request.body?.email;
      /** @type {string} */
      const password = ctx.request.body?.password;

      if (!email || !password) {
        return ctx.badRequest('Missing email or password');
      }

      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      strapi.log.info(`🔵 Authenticating ${email} via Keycloak Passport...`);

      // 🔑 Authenticate with Keycloak
      const tokenResponse = await axios.post(
        `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          username: email,
          password,
          grant_type: 'password',
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string} */
      const access_token = tokenResponse.data.access_token;
      strapi.log.info(`✅ ${email} successfully authenticated via Keycloak.`);

      // 🔍 Fetch user details from Keycloak
      const userInfoResponse = await axios.get(
        `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_USERINFO_URL}`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );

      /** @type {Object} */
      const userInfo = userInfoResponse.data;

      // 🔄 Find or create Strapi admin user
      /** @type {Object} */
      const adminUser = await strapi
        .service('plugin::strapi-keycloak-passport.adminUserService')
        .findOrCreate(userInfo);

      // 🔥 Generate Strapi JWT
      /** @type {string} */
      const jwt = await strapi.admin.services.token.createJwtToken(adminUser);

      // ✅ Store authenticated user in `ctx.state.user`
      ctx.session = {
        ...ctx.session,
        user: adminUser
      };

      return ctx.send({
        data: {
          token: jwt,
          user: {
            id: adminUser.id,
            firstname: adminUser.firstname,
            lastname: adminUser.lastname,
            username: adminUser.username || null,
            email: adminUser.email,
            isActive: adminUser.isActive,
            blocked: adminUser.blocked || false,
            createdAt: adminUser.createdAt,
            updatedAt: adminUser.updatedAt,
          },
        },
      });
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;
      const errorDetails = {
        status: error.response?.status || error?.status || 400,
        message: error.response?.data?.error_description || error.response?.data?.error || error?.message || 'Invalid credentials',
        name: error?.name ?? 'ApplicationError',
        endpoint: `${config?.KEYCLOAK_AUTH_URL}${config?.KEYCLOAK_TOKEN_URL}`,
        responseData: error.response?.data || null,
      };

      strapi.log.error(
        `🔴 Authentication Failed for ${ctx.request.body?.email || 'unknown user'}:`,
        isDebugMode ? errorDetails : (error.response?.data || error.message)
      );

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Full error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          responseStatus: error.response?.status,
          responseData: error.response?.data,
          requestUrl: error.config?.url,
        });
      }

      return ctx.badRequest('Invalid credentials', {
        error: {
          status: errorDetails.status,
          name: errorDetails.name,
          message: isDebugMode ? errorDetails.message : 'Invalid credentials',
          details: isDebugMode ? {
            keycloakError: error.response?.data?.error,
            keycloakErrorDescription: error.response?.data?.error_description,
            endpoint: errorDetails.endpoint,
          } : {},
        },
      });
    }
  },

  /**
   * Initiates OAuth2 Authorization Code flow for Keycloak 18+.
   * Redirects the user to Keycloak's authorization endpoint.
   *
   * @async
   * @function authorize
   * @param {Object} ctx - Koa context.
   * @returns {void} Redirects to Keycloak authorization URL.
   */
  async authorize(ctx) {
    try {
      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      /** @type {string} */
      const redirectUri = config.KEYCLOAK_REDIRECT_URI;

      if (!redirectUri) {
        return ctx.badRequest('KEYCLOAK_REDIRECT_URI is not configured');
      }

      // Generate a cryptographically secure state parameter for CSRF protection
      const state = generateState();

      // Store state in session for validation during callback
      ctx.session = {
        ...ctx.session,
        oauth2State: state,
      };

      // Build the Keycloak authorization URL
      const authUrl = buildAuthorizationUrl(config, redirectUri, state);

      strapi.log.info('🔵 Redirecting to Keycloak authorization endpoint...');
      return ctx.redirect(authUrl.toString());
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('🔴 Failed to initiate OAuth2 authorization:', error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Authorization initiation error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          redirectUri: config?.KEYCLOAK_REDIRECT_URI,
          authUrl: config?.KEYCLOAK_AUTH_URL,
          realm: config?.KEYCLOAK_REALM,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to initiate authorization: ${error.message}` : 'Failed to initiate authorization');
    }
  },

  /**
   * Handles the OAuth2 callback from Keycloak after user authorization.
   * Exchanges the authorization code for tokens and creates/updates the admin user.
   *
   * @async
   * @function callback
   * @param {Object} ctx - Koa context.
   * @param {Object} ctx.query - Query parameters.
   * @param {string} ctx.query.code - The authorization code from Keycloak.
   * @param {string} ctx.query.state - The state parameter for CSRF validation.
   * @returns {Promise<void>} Redirects to admin panel with JWT token.
   * @throws {Error} If token exchange fails or user creation fails.
   */
  async callback(ctx) {
    try {
      const { code, state, error, error_description } = ctx.query;
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      // Handle error response from Keycloak
      if (error) {
        strapi.log.error(`🔴 Keycloak authorization error: ${error} - ${error_description}`);

        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Keycloak authorization error details:', {
            error,
            errorDescription: error_description,
            queryParams: ctx.query,
          });
        }

        const errorParam = isDebugMode
          ? `authorization_failed&error_detail=${encodeURIComponent(error_description || error)}`
          : 'authorization_failed';
        return ctx.redirect(`/admin/auth/login?error=${errorParam}`);
      }

      if (!code) {
        return ctx.badRequest('Missing authorization code');
      }

      // Validate state parameter (CSRF protection)
      if (ctx.session?.oauth2State && state !== ctx.session.oauth2State) {
        strapi.log.error('🔴 Invalid state parameter - possible CSRF attack');

        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - CSRF state mismatch:', {
            expectedState: ctx.session?.oauth2State,
            receivedState: state,
          });
        }

        return ctx.badRequest('Invalid state parameter');
      }

      /** @type {string} */
      const redirectUri = config.KEYCLOAK_REDIRECT_URI;

      // Exchange authorization code for tokens
      const tokenResponse = await axios.post(
        `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string} */
      const access_token = tokenResponse.data.access_token;
      strapi.log.info('✅ Successfully exchanged authorization code for tokens.');

      // Fetch user details from Keycloak
      const userInfoResponse = await axios.get(
        `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );

      /** @type {Object} */
      const userInfo = userInfoResponse.data;
      strapi.log.info(`🔵 Authenticating ${userInfo.email} via Keycloak OAuth2...`);

      // Find or create Strapi admin user
      /** @type {Object} */
      const adminUser = await strapi
        .service('plugin::strapi-keycloak-passport.adminUserService')
        .findOrCreate(userInfo);

      // Generate Strapi JWT
      /** @type {string} */
      const jwt = await strapi.admin.services.token.createJwtToken(adminUser);

      strapi.log.info(`✅ ${userInfo.email} successfully authenticated via Keycloak OAuth2.`);

      // Clear OAuth2 state from session
      if (ctx.session) {
        delete ctx.session.oauth2State;
      }

      // Store authenticated user in session
      ctx.session = {
        ...ctx.session,
        user: adminUser,
      };

      // Redirect to admin panel with the JWT token
      return ctx.redirect(`/admin/auth/login?loginToken=${jwt}`);
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('🔴 OAuth2 callback failed:', error.response?.data || error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - OAuth2 callback error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          responseStatus: error.response?.status,
          responseData: error.response?.data,
          requestUrl: error.config?.url,
          tokenEndpoint: `${config?.KEYCLOAK_AUTH_URL}/realms/${config?.KEYCLOAK_REALM}/protocol/openid-connect/token`,
          userInfoEndpoint: `${config?.KEYCLOAK_AUTH_URL}/realms/${config?.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        });
      }

      const errorMessage = isDebugMode
        ? `authentication_failed&error_detail=${encodeURIComponent(error.response?.data?.error_description || error.message)}`
        : 'authentication_failed';
      return ctx.redirect(`/admin/auth/login?error=${errorMessage}`);
    }
  },

  /**
   * Returns the Keycloak logout URL for the frontend to redirect to.
   * This properly terminates the Keycloak session.
   *
   * @async
   * @function getLogoutUrl
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} The logout URL response.
   */
  async getLogoutUrl(ctx) {
    try {
      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      /** @type {string} */
      const postLogoutRedirectUri = config.KEYCLOAK_LOGOUT_REDIRECT_URI || `${ctx.request.origin}/admin/auth/login`;

      // Build the Keycloak logout URL
      const logoutUrl = new URL(`${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
      logoutUrl.searchParams.set('client_id', config.KEYCLOAK_CLIENT_ID);
      logoutUrl.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);

      strapi.log.info('🔵 Generated Keycloak logout URL.');
      return ctx.send({ logoutUrl: logoutUrl.toString() });
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('🔴 Failed to generate logout URL:', error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Logout URL generation error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          authUrl: config?.KEYCLOAK_AUTH_URL,
          realm: config?.KEYCLOAK_REALM,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to generate logout URL: ${error.message}` : 'Failed to generate logout URL');
    }
  },

  /**
   * Returns the Keycloak authorization URL for the frontend to redirect to.
   * Used for Keycloak 18+ OAuth2 Authorization Code flow.
   *
   * @async
   * @function getAuthorizationUrl
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} The authorization URL response.
   */
  async getAuthorizationUrl(ctx) {
    try {
      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      /** @type {string} */
      const redirectUri = config.KEYCLOAK_REDIRECT_URI;

      if (!redirectUri) {
        return ctx.badRequest('KEYCLOAK_REDIRECT_URI is not configured');
      }

      // Generate a cryptographically secure state parameter for CSRF protection
      const state = generateState();

      // Store state in session for validation during callback
      ctx.session = {
        ...ctx.session,
        oauth2State: state,
      };

      // Build the Keycloak authorization URL
      const authUrl = buildAuthorizationUrl(config, redirectUri, state);

      strapi.log.info('🔵 Generated Keycloak authorization URL.');
      return ctx.send({ authorizationUrl: authUrl.toString(), state });
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('🔴 Failed to generate authorization URL:', error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Authorization URL generation error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          authUrl: config?.KEYCLOAK_AUTH_URL,
          realm: config?.KEYCLOAK_REALM,
          redirectUri: config?.KEYCLOAK_REDIRECT_URI,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to generate authorization URL: ${error.message}` : 'Failed to generate authorization URL');
    }
  },
};