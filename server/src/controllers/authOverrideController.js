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

      strapi.log.debug('🔍 Login request body:', { email, hasPassword: !!password });

      if (!email || !password) {
        strapi.log.warn('⚠️ Missing email or password in login request');
        return ctx.badRequest('Missing email or password');
      }

      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      strapi.log.info(`🔵 Authenticating ${email} via Keycloak Passport...`);
      
      // Construct the token URL - support both full URLs and path-based config
      let tokenUrl;
      if (config.KEYCLOAK_TOKEN_URL) {
        // If KEYCLOAK_TOKEN_URL is a full URL (starts with http), use it directly
        tokenUrl = config.KEYCLOAK_TOKEN_URL.startsWith('http') 
          ? config.KEYCLOAK_TOKEN_URL
          : `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`;
      } else {
        // Fallback: construct from base URL and realm
        tokenUrl = `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`;
      }
      
      strapi.log.debug('🔍 Keycloak token endpoint:', tokenUrl);
      strapi.log.debug('🔍 Keycloak config:', {
        authUrl: config.KEYCLOAK_AUTH_URL,
        realm: config.KEYCLOAK_REALM,
        clientId: config.KEYCLOAK_CLIENT_ID,
        hasClientSecret: !!config.KEYCLOAK_CLIENT_SECRET,
      });

      // 🔑 Authenticate with Keycloak
      const tokenRequestData = {
        client_id: config.KEYCLOAK_CLIENT_ID,
        client_secret: config.KEYCLOAK_CLIENT_SECRET,
        username: email,
        password,
        grant_type: 'password',
        scope: config.KEYCLOAK_SCOPE || 'openid email profile', // Required for userinfo endpoint access
      };
      strapi.log.debug('🔍 Token request (password hidden):', {
        client_id: tokenRequestData.client_id,
        username: tokenRequestData.username,
        grant_type: tokenRequestData.grant_type,
        scope: tokenRequestData.scope,
        hasClientSecret: !!tokenRequestData.client_secret,
        hasPassword: !!tokenRequestData.password,
      });
      
      const tokenResponse = await axios.post(
        tokenUrl,
        new URLSearchParams(tokenRequestData).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string} */
      const access_token = tokenResponse.data.access_token;
      strapi.log.info(`✅ ${email} successfully authenticated via Keycloak.`);
      strapi.log.debug('🔍 Keycloak token response:', {
        hasAccessToken: !!access_token,
        tokenType: tokenResponse.data.token_type,
        expiresIn: tokenResponse.data.expires_in,
        hasRefreshToken: !!tokenResponse.data.refresh_token,
        scope: tokenResponse.data.scope,
        accessTokenPreview: access_token ? `${access_token.substring(0, 20)}...` : 'none',
      });

      // 🔍 Fetch user details from Keycloak
      let userInfoUrl;
      if (config.KEYCLOAK_USERINFO_URL) {
        // If KEYCLOAK_USERINFO_URL is a full URL (starts with http), use it directly
        userInfoUrl = config.KEYCLOAK_USERINFO_URL.startsWith('http')
          ? config.KEYCLOAK_USERINFO_URL
          : `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_USERINFO_URL}`;
      } else {
        // Fallback: construct from base URL and realm
        userInfoUrl = `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`;
      }
      
      strapi.log.debug('🔍 Keycloak userinfo endpoint:', userInfoUrl);
      strapi.log.debug('🔍 Requesting userinfo with token:', {
        url: userInfoUrl,
        hasAuthHeader: true,
        tokenPreview: access_token ? `${access_token.substring(0, 20)}...` : 'none',
      });
      
      const userInfoResponse = await axios.get(
        userInfoUrl,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );

      /** @type {Object} */
      const userInfo = userInfoResponse.data;
      strapi.log.debug('🔍 Keycloak user info:', {
        email: userInfo.email,
        sub: userInfo.sub,
        preferred_username: userInfo.preferred_username,
        given_name: userInfo.given_name,
        family_name: userInfo.family_name,
      });

      // 🔄 Find or create Strapi admin user
      strapi.log.debug('🔍 Finding or creating admin user...');
      /** @type {Object} */
      const adminUser = await strapi
        .service('plugin::strapi-keycloak-passport.adminUserService')
        .findOrCreate(userInfo);
      
      strapi.log.debug('🔍 Admin user result:', {
        id: adminUser?.id,
        email: adminUser?.email,
        isActive: adminUser?.isActive,
        hasRoles: !!adminUser?.roles,
        roleCount: adminUser?.roles?.length,
      });

      // 🔥 Generate Strapi JWT using session manager (Strapi 5)
      strapi.log.debug('🔍 Generating JWT token...');
      
      const sessionManager = strapi.sessionManager;
      if (!sessionManager) {
        throw new Error('sessionManager is not supported. Please upgrade to Strapi v5.24.1 or later.');
      }
      
      const userId = String(adminUser.id);
      const deviceId = crypto.randomUUID();
      const rememberMe = !!config.REMEMBER_ME;
      
      // Generate refresh token
      const {token: refreshToken} = await sessionManager('admin').generateRefreshToken(userId, deviceId, {
        type: rememberMe ? 'refresh' : 'session',
      });
      
      // Set refresh token in cookie
      const cookieOptions = {};
      ctx.cookies.set('strapi_admin_refresh', refreshToken, cookieOptions);
      
      // Generate access token
      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        throw new Error(accessResult.error);
      }
      const {token: jwt} = accessResult;
      
      strapi.log.debug('🔍 JWT generated:', { hasToken: !!jwt, tokenLength: jwt?.length });

      // ✅ Store authenticated user in `ctx.state.user`
      ctx.session = {
        ...ctx.session,
        user: adminUser
      };
      strapi.log.debug('🔍 Session updated with user');

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
      const errorDetails = {
        status: error.response?.status || error?.status,
        name: error?.name,
        message: error?.message,
        url: error.config?.url,
        method: error.config?.method,
        responseData: error.response?.data,
        code: error.code,
      };
      
      strapi.log.error(
        `🔴 Authentication Failed for ${ctx.request.body?.email || 'unknown user'}:`,
      );
      strapi.log.error('🔍 Error details:', errorDetails);
      strapi.log.debug('🔍 Full error stack:', error.stack);

      return ctx.badRequest('Invalid credentials', {
        error: {
          status: error.response?.status || error?.status || 400,
          name: error?.name || 'ApplicationError',
          message: error?.message || 'Invalid credentials',
          details: {
            error: errorDetails
          },
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
      strapi.log.error('🔴 Failed to initiate OAuth2 authorization:', error.message);
      return ctx.badRequest('Failed to initiate authorization');
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

      // Handle error response from Keycloak
      if (error) {
        strapi.log.error(`🔴 Keycloak authorization error: ${error} - ${error_description}`);
        return ctx.redirect('/admin/auth/login?error=authorization_failed');
      }

      if (!code) {
        return ctx.badRequest('Missing authorization code');
      }

      // Validate state parameter (CSRF protection)
      if (ctx.session?.oauth2State && state !== ctx.session.oauth2State) {
        strapi.log.error('🔴 Invalid state parameter - possible CSRF attack');
        return ctx.badRequest('Invalid state parameter');
      }

      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

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

      // Generate Strapi JWT using session manager (Strapi 5)
      const sessionManager = strapi.sessionManager;
      if (!sessionManager) {
        throw new Error('sessionManager is not supported. Please upgrade to Strapi v5.24.1 or later.');
      }
      
      const userId = String(adminUser.id);
      const deviceId = crypto.randomUUID();
      const rememberMe = !!config.REMEMBER_ME;
      
      // Generate refresh token
      const {token: refreshToken} = await sessionManager('admin').generateRefreshToken(userId, deviceId, {
        type: rememberMe ? 'refresh' : 'session',
      });
      
      // Set refresh token in cookie
      const cookieOptions = {};
      ctx.cookies.set('strapi_admin_refresh', refreshToken, cookieOptions);
      
      // Generate access token
      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        throw new Error(accessResult.error);
      }
      const {token: jwt} = accessResult;

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
      strapi.log.error('🔴 OAuth2 callback failed:', error.response?.data || error.message);
      return ctx.redirect('/admin/auth/login?error=authentication_failed');
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

      // Build the Keycloak logout URL - support both full URLs and path-based config
      let logoutUrl;
      if (config.KEYCLOAK_LOGOUT_URL) {
        // If KEYCLOAK_LOGOUT_URL is a full URL (starts with http), use it directly
        if (config.KEYCLOAK_LOGOUT_URL.startsWith('http')) {
          logoutUrl = new URL(config.KEYCLOAK_LOGOUT_URL);
        } else {
          // Path-based: concatenate with base URL
          logoutUrl = new URL(`${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_LOGOUT_URL}`);
        }
      } else {
        // Fallback: construct from base URL and realm
        logoutUrl = new URL(`${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
      }
      
      logoutUrl.searchParams.set('client_id', config.KEYCLOAK_CLIENT_ID);
      logoutUrl.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);

      strapi.log.info('🔵 Generated Keycloak logout URL.');
      return ctx.send({ logoutUrl: logoutUrl.toString() });
    } catch (error) {
      strapi.log.error('🔴 Failed to generate logout URL:', error.message);
      return ctx.badRequest('Failed to generate logout URL');
    }
  },

  /**
   * Performs complete logout: destroys Strapi session, clears cookies, 
   * revokes Keycloak tokens, and redirects to Keycloak logout.
   * This overrides Strapi 5's default /admin/logout endpoint.
   *
   * @async
   * @function logout
   * @param {Object} ctx - Koa context.
   * @returns {Promise<void>} Returns JSON response or redirects to Keycloak logout.
   */
  async logout(ctx) {
    try {
      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      strapi.log.info('🔵 Initiating logout process...');
      strapi.log.debug('🔍 Request method:', ctx.request.method);
      strapi.log.debug('🔍 Request URL:', ctx.request.url);
      strapi.log.debug('🔍 Accept header:', ctx.request.headers.accept);

      // 1. Get refresh token from cookie for revocation
      const refreshToken = ctx.cookies.get('strapi_admin_refresh');
      strapi.log.debug('🔍 Refresh token present:', !!refreshToken);
      
      // 2. Destroy Strapi session using session manager
      let sessionDestroyed = false;
      if (refreshToken && strapi.sessionManager) {
        try {
          const sessionManager = strapi.sessionManager('admin');
          await sessionManager.destroyRefreshToken(refreshToken);
          strapi.log.info('✅ Strapi session destroyed via session manager');
          sessionDestroyed = true;
        } catch (error) {
          strapi.log.warn('⚠️ Failed to destroy Strapi session:', error.message);
          strapi.log.debug('🔍 Session destruction error:', error);
        }
      } else {
        strapi.log.warn('⚠️ Cannot destroy session - missing refresh token or session manager');
      }

      // 3. Clear session cookies
      ctx.cookies.set('strapi_admin_refresh', null, {
        maxAge: 0,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        path: '/',
        sameSite: 'lax',
      });
      strapi.log.info('✅ Session cookies cleared');

      // 4. Clear ctx.session
      if (ctx.session) {
        ctx.session = null;
      }

      // 5. Revoke Keycloak tokens if refresh token exists
      let tokensRevoked = false;
      if (refreshToken) {
        try {
          // Construct revocation endpoint URL
          let revocationUrl;
          if (config.KEYCLOAK_TOKEN_URL) {
            if (config.KEYCLOAK_TOKEN_URL.startsWith('http')) {
              // Full URL: extract base and construct revoke endpoint
              const baseUrl = config.KEYCLOAK_TOKEN_URL.split('/protocol/')[0];
              revocationUrl = `${baseUrl}/protocol/openid-connect/revoke`;
            } else {
              // Path-based: replace token with revoke
              const revokePath = config.KEYCLOAK_TOKEN_URL.replace('/token', '/revoke');
              revocationUrl = `${config.KEYCLOAK_AUTH_URL}${revokePath}`;
            }
          } else {
            // Fallback: construct from base URL and realm
            revocationUrl = `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/revoke`;
          }

          strapi.log.debug('🔍 Revoking token at:', revocationUrl);
          
          const revocationResponse = await axios.post(
            revocationUrl,
            new URLSearchParams({
              client_id: config.KEYCLOAK_CLIENT_ID,
              client_secret: config.KEYCLOAK_CLIENT_SECRET,
              token: refreshToken,
              token_type_hint: 'refresh_token',
            }).toString(),
            { 
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              validateStatus: (status) => status < 500, // Accept 4xx responses
            }
          );
          
          strapi.log.info('✅ Keycloak tokens revoked');
          strapi.log.debug('🔍 Revocation response status:', revocationResponse.status);
          tokensRevoked = true;
        } catch (error) {
          strapi.log.warn('⚠️ Failed to revoke Keycloak tokens:', error.message);
          strapi.log.debug('🔍 Token revocation error:', error.response?.data || error);
          // Continue with logout even if revocation fails
        }
      }

      // 6. Build Keycloak logout URL with callback
      const logoutCallbackUri = `${ctx.request.origin}/strapi-keycloak-passport/logout-callback`;
      strapi.log.debug('🔍 Logout callback URI:', logoutCallbackUri);

      let keycloakLogoutUrl;
      if (config.KEYCLOAK_LOGOUT_URL) {
        if (config.KEYCLOAK_LOGOUT_URL.startsWith('http')) {
          keycloakLogoutUrl = new URL(config.KEYCLOAK_LOGOUT_URL);
        } else {
          keycloakLogoutUrl = new URL(`${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_LOGOUT_URL}`);
        }
      } else {
        keycloakLogoutUrl = new URL(`${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
      }
      
      keycloakLogoutUrl.searchParams.set('client_id', config.KEYCLOAK_CLIENT_ID);
      keycloakLogoutUrl.searchParams.set('post_logout_redirect_uri', logoutCallbackUri);

      strapi.log.info('✅ Logout completed, initiating Keycloak logout');
      strapi.log.debug('🔍 Keycloak logout URL:', keycloakLogoutUrl.toString());
      
      // 7. Check if request expects JSON (from admin panel) or redirect
      const expectsJson = ctx.request.headers.accept?.includes('application/json');
      
      if (expectsJson) {
        // Return JSON response with logout URL for admin panel to handle
        strapi.log.debug('🔍 Returning JSON response with logout URL');
        return ctx.send({
          data: {
            logoutUrl: keycloakLogoutUrl.toString(),
            sessionDestroyed,
            tokensRevoked,
          },
        });
      } else {
        // Direct redirect for non-JSON requests
        strapi.log.debug('🔍 Redirecting to Keycloak logout');
        return ctx.redirect(keycloakLogoutUrl.toString());
      }
    } catch (error) {
      strapi.log.error('🔴 Logout failed:', error.message);
      strapi.log.debug('🔍 Full error:', error.stack);
      
      // Even if logout fails, try to clear cookies and redirect
      try {
        ctx.cookies.set('strapi_admin_refresh', null, {
          maxAge: 0,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          path: '/',
        });
      } catch (cookieError) {
        strapi.log.debug('🔍 Failed to clear cookies:', cookieError.message);
      }
      
      // Check if expecting JSON response
      const expectsJson = ctx.request.headers.accept?.includes('application/json');
      if (expectsJson) {
        return ctx.send({
          data: {
            logoutUrl: '/admin/auth/login',
            sessionDestroyed: false,
            tokensRevoked: false,
            error: error.message,
          },
        });
      } else {
        const redirectUri = config?.KEYCLOAK_LOGOUT_REDIRECT_URI || '/admin/auth/login';
        return ctx.redirect(redirectUri);
      }
    }
  },

  /**
   * Handles the callback after Keycloak logout completes.
   * This is where Keycloak redirects after terminating the SSO session.
   *
   * @async
   * @function logoutCallback
   * @param {Object} ctx - Koa context.
   * @returns {Promise<void>} Redirects to final logout destination.
   */
  async logoutCallback(ctx) {
    try {
      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      
      strapi.log.info('🔵 Logout callback received from Keycloak');
      strapi.log.debug('🔍 Query params:', ctx.query);
      
      // Final redirect after Keycloak logout
      const finalRedirectUri = config.KEYCLOAK_LOGOUT_REDIRECT_URI || '/admin/auth/login';
      
      strapi.log.info('✅ Logout flow completed, redirecting to:', finalRedirectUri);
      return ctx.redirect(finalRedirectUri);
    } catch (error) {
      strapi.log.error('🔴 Logout callback failed:', error.message);
      // Redirect to login even on error
      return ctx.redirect('/admin/auth/login');
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
      strapi.log.error('🔴 Failed to generate authorization URL:', error.message);
      return ctx.badRequest('Failed to generate authorization URL');
    }
  },
};