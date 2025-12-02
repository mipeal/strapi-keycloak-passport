import axios from "axios";
import crypto from "crypto";
function generateState() {
  return crypto.randomUUID();
}
function buildAuthorizationUrl(config2, redirectUri, state) {
  const authUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/auth`);
  authUrl.searchParams.set("client_id", config2.KEYCLOAK_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("state", state);
  return authUrl;
}
const authOverrideController = {
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
      const email = ctx.request.body?.email;
      const password = ctx.request.body?.password;
      strapi.log.debug("🔍 Login request body:", { email, hasPassword: !!password });
      if (!email || !password) {
        strapi.log.warn("⚠️ Missing email or password in login request");
        return ctx.badRequest("Missing email or password");
      }
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      strapi.log.info(`🔵 Authenticating ${email} via Keycloak Passport...`);
      let tokenUrl;
      if (config2.KEYCLOAK_TOKEN_URL) {
        tokenUrl = config2.KEYCLOAK_TOKEN_URL.startsWith("http") ? config2.KEYCLOAK_TOKEN_URL : `${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_TOKEN_URL}`;
      } else {
        tokenUrl = `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/token`;
      }
      strapi.log.debug("🔍 Keycloak token endpoint:", tokenUrl);
      strapi.log.debug("🔍 Keycloak config:", {
        authUrl: config2.KEYCLOAK_AUTH_URL,
        realm: config2.KEYCLOAK_REALM,
        clientId: config2.KEYCLOAK_CLIENT_ID,
        hasClientSecret: !!config2.KEYCLOAK_CLIENT_SECRET
      });
      const tokenRequestData = {
        client_id: config2.KEYCLOAK_CLIENT_ID,
        client_secret: config2.KEYCLOAK_CLIENT_SECRET,
        username: email,
        password,
        grant_type: "password",
        scope: config2.KEYCLOAK_SCOPE || "openid email profile"
        // Required for userinfo endpoint access
      };
      strapi.log.debug("🔍 Token request (password hidden):", {
        client_id: tokenRequestData.client_id,
        username: tokenRequestData.username,
        grant_type: tokenRequestData.grant_type,
        scope: tokenRequestData.scope,
        hasClientSecret: !!tokenRequestData.client_secret,
        hasPassword: !!tokenRequestData.password
      });
      const tokenResponse = await axios.post(
        tokenUrl,
        new URLSearchParams(tokenRequestData).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const access_token = tokenResponse.data.access_token;
      strapi.log.info(`✅ ${email} successfully authenticated via Keycloak.`);
      strapi.log.debug("🔍 Keycloak token response:", {
        hasAccessToken: !!access_token,
        tokenType: tokenResponse.data.token_type,
        expiresIn: tokenResponse.data.expires_in,
        hasRefreshToken: !!tokenResponse.data.refresh_token,
        scope: tokenResponse.data.scope,
        accessTokenPreview: access_token ? `${access_token.substring(0, 20)}...` : "none"
      });
      let userInfoUrl;
      if (config2.KEYCLOAK_USERINFO_URL) {
        userInfoUrl = config2.KEYCLOAK_USERINFO_URL.startsWith("http") ? config2.KEYCLOAK_USERINFO_URL : `${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_USERINFO_URL}`;
      } else {
        userInfoUrl = `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`;
      }
      strapi.log.debug("🔍 Keycloak userinfo endpoint:", userInfoUrl);
      strapi.log.debug("🔍 Requesting userinfo with token:", {
        url: userInfoUrl,
        hasAuthHeader: true,
        tokenPreview: access_token ? `${access_token.substring(0, 20)}...` : "none"
      });
      const userInfoResponse = await axios.get(
        userInfoUrl,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
      const userInfo = userInfoResponse.data;
      strapi.log.debug("🔍 Keycloak user info:", {
        email: userInfo.email,
        sub: userInfo.sub,
        preferred_username: userInfo.preferred_username,
        given_name: userInfo.given_name,
        family_name: userInfo.family_name
      });
      strapi.log.debug("🔍 Finding or creating admin user...");
      const adminUser = await strapi.service("plugin::strapi-keycloak-passport.adminUserService").findOrCreate(userInfo);
      strapi.log.debug("🔍 Admin user result:", {
        id: adminUser?.id,
        email: adminUser?.email,
        isActive: adminUser?.isActive,
        hasRoles: !!adminUser?.roles,
        roleCount: adminUser?.roles?.length
      });
      strapi.log.debug("🔍 Generating JWT token...");
      const sessionManager = strapi.sessionManager;
      if (!sessionManager) {
        throw new Error("sessionManager is not supported. Please upgrade to Strapi v5.24.1 or later.");
      }
      const userId = String(adminUser.id);
      const deviceId = crypto.randomUUID();
      const rememberMe = !!config2.REMEMBER_ME;
      const { token: refreshToken } = await sessionManager("admin").generateRefreshToken(userId, deviceId, {
        type: rememberMe ? "refresh" : "session"
      });
      const cookieOptions = {};
      ctx.cookies.set("strapi_admin_refresh", refreshToken, cookieOptions);
      const accessResult = await sessionManager("admin").generateAccessToken(refreshToken);
      if ("error" in accessResult) {
        throw new Error(accessResult.error);
      }
      const { token: jwt } = accessResult;
      strapi.log.debug("🔍 JWT generated:", { hasToken: !!jwt, tokenLength: jwt?.length });
      ctx.session = {
        ...ctx.session,
        user: adminUser
      };
      strapi.log.debug("🔍 Session updated with user");
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
            updatedAt: adminUser.updatedAt
          }
        }
      });
    } catch (error) {
      const errorDetails = {
        status: error.response?.status || error?.status,
        name: error?.name,
        message: error?.message,
        url: error.config?.url,
        method: error.config?.method,
        responseData: error.response?.data,
        code: error.code
      };
      strapi.log.error(
        `🔴 Authentication Failed for ${ctx.request.body?.email || "unknown user"}:`
      );
      strapi.log.error("🔍 Error details:", errorDetails);
      strapi.log.debug("🔍 Full error stack:", error.stack);
      return ctx.badRequest("Invalid credentials", {
        error: {
          status: error.response?.status || error?.status || 400,
          name: error?.name || "ApplicationError",
          message: error?.message || "Invalid credentials",
          details: {
            error: errorDetails
          }
        }
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
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      const redirectUri = config2.KEYCLOAK_REDIRECT_URI;
      if (!redirectUri) {
        return ctx.badRequest("KEYCLOAK_REDIRECT_URI is not configured");
      }
      const state = generateState();
      ctx.session = {
        ...ctx.session,
        oauth2State: state
      };
      const authUrl = buildAuthorizationUrl(config2, redirectUri, state);
      strapi.log.info("🔵 Redirecting to Keycloak authorization endpoint...");
      return ctx.redirect(authUrl.toString());
    } catch (error) {
      strapi.log.error("🔴 Failed to initiate OAuth2 authorization:", error.message);
      return ctx.badRequest("Failed to initiate authorization");
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
      if (error) {
        strapi.log.error(`🔴 Keycloak authorization error: ${error} - ${error_description}`);
        return ctx.redirect("/admin/auth/login?error=authorization_failed");
      }
      if (!code) {
        return ctx.badRequest("Missing authorization code");
      }
      if (ctx.session?.oauth2State && state !== ctx.session.oauth2State) {
        strapi.log.error("🔴 Invalid state parameter - possible CSRF attack");
        return ctx.badRequest("Invalid state parameter");
      }
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      const redirectUri = config2.KEYCLOAK_REDIRECT_URI;
      const tokenResponse = await axios.post(
        `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/token`,
        new URLSearchParams({
          client_id: config2.KEYCLOAK_CLIENT_ID,
          client_secret: config2.KEYCLOAK_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri
        }).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const access_token = tokenResponse.data.access_token;
      strapi.log.info("✅ Successfully exchanged authorization code for tokens.");
      const userInfoResponse = await axios.get(
        `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
      const userInfo = userInfoResponse.data;
      strapi.log.info(`🔵 Authenticating ${userInfo.email} via Keycloak OAuth2...`);
      const adminUser = await strapi.service("plugin::strapi-keycloak-passport.adminUserService").findOrCreate(userInfo);
      const sessionManager = strapi.sessionManager;
      if (!sessionManager) {
        throw new Error("sessionManager is not supported. Please upgrade to Strapi v5.24.1 or later.");
      }
      const userId = String(adminUser.id);
      const deviceId = crypto.randomUUID();
      const rememberMe = !!config2.REMEMBER_ME;
      const { token: refreshToken } = await sessionManager("admin").generateRefreshToken(userId, deviceId, {
        type: rememberMe ? "refresh" : "session"
      });
      const cookieOptions = {};
      ctx.cookies.set("strapi_admin_refresh", refreshToken, cookieOptions);
      const accessResult = await sessionManager("admin").generateAccessToken(refreshToken);
      if ("error" in accessResult) {
        throw new Error(accessResult.error);
      }
      const { token: jwt } = accessResult;
      strapi.log.info(`✅ ${userInfo.email} successfully authenticated via Keycloak OAuth2.`);
      if (ctx.session) {
        delete ctx.session.oauth2State;
      }
      ctx.session = {
        ...ctx.session,
        user: adminUser
      };
      return ctx.redirect(`/admin/auth/login?loginToken=${jwt}`);
    } catch (error) {
      strapi.log.error("🔴 OAuth2 callback failed:", error.response?.data || error.message);
      return ctx.redirect("/admin/auth/login?error=authentication_failed");
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
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      const postLogoutRedirectUri = config2.KEYCLOAK_LOGOUT_REDIRECT_URI || `${ctx.request.origin}/admin/auth/login`;
      let logoutUrl;
      if (config2.KEYCLOAK_LOGOUT_URL) {
        if (config2.KEYCLOAK_LOGOUT_URL.startsWith("http")) {
          logoutUrl = new URL(config2.KEYCLOAK_LOGOUT_URL);
        } else {
          logoutUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_LOGOUT_URL}`);
        }
      } else {
        logoutUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
      }
      logoutUrl.searchParams.set("client_id", config2.KEYCLOAK_CLIENT_ID);
      logoutUrl.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
      strapi.log.info("🔵 Generated Keycloak logout URL.");
      return ctx.send({ logoutUrl: logoutUrl.toString() });
    } catch (error) {
      strapi.log.error("🔴 Failed to generate logout URL:", error.message);
      return ctx.badRequest("Failed to generate logout URL");
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
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      strapi.log.info("🔵 Initiating logout process...");
      strapi.log.debug("🔍 Request method:", ctx.request.method);
      strapi.log.debug("🔍 Request URL:", ctx.request.url);
      strapi.log.debug("🔍 Accept header:", ctx.request.headers.accept);
      const refreshToken = ctx.cookies.get("strapi_admin_refresh");
      strapi.log.debug("🔍 Refresh token present:", !!refreshToken);
      let sessionDestroyed = false;
      if (refreshToken && strapi.sessionManager) {
        try {
          const sessionManager = strapi.sessionManager("admin");
          await sessionManager.destroyRefreshToken(refreshToken);
          strapi.log.info("✅ Strapi session destroyed via session manager");
          sessionDestroyed = true;
        } catch (error) {
          strapi.log.warn("⚠️ Failed to destroy Strapi session:", error.message);
          strapi.log.debug("🔍 Session destruction error:", error);
        }
      } else {
        strapi.log.warn("⚠️ Cannot destroy session - missing refresh token or session manager");
      }
      ctx.cookies.set("strapi_admin_refresh", null, {
        maxAge: 0,
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        path: "/",
        sameSite: "lax"
      });
      strapi.log.info("✅ Session cookies cleared");
      if (ctx.session) {
        ctx.session = null;
      }
      let tokensRevoked = false;
      if (refreshToken) {
        try {
          let revocationUrl;
          if (config2.KEYCLOAK_TOKEN_URL) {
            if (config2.KEYCLOAK_TOKEN_URL.startsWith("http")) {
              const baseUrl = config2.KEYCLOAK_TOKEN_URL.split("/protocol/")[0];
              revocationUrl = `${baseUrl}/protocol/openid-connect/revoke`;
            } else {
              const revokePath = config2.KEYCLOAK_TOKEN_URL.replace("/token", "/revoke");
              revocationUrl = `${config2.KEYCLOAK_AUTH_URL}${revokePath}`;
            }
          } else {
            revocationUrl = `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/revoke`;
          }
          strapi.log.debug("🔍 Revoking token at:", revocationUrl);
          const revocationResponse = await axios.post(
            revocationUrl,
            new URLSearchParams({
              client_id: config2.KEYCLOAK_CLIENT_ID,
              client_secret: config2.KEYCLOAK_CLIENT_SECRET,
              token: refreshToken,
              token_type_hint: "refresh_token"
            }).toString(),
            {
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              validateStatus: (status) => status < 500
              // Accept 4xx responses
            }
          );
          strapi.log.info("✅ Keycloak tokens revoked");
          strapi.log.debug("🔍 Revocation response status:", revocationResponse.status);
          tokensRevoked = true;
        } catch (error) {
          strapi.log.warn("⚠️ Failed to revoke Keycloak tokens:", error.message);
          strapi.log.debug("🔍 Token revocation error:", error.response?.data || error);
        }
      }
      const logoutCallbackUri = `${ctx.request.origin}/strapi-keycloak-passport/logout-callback`;
      strapi.log.debug("🔍 Logout callback URI:", logoutCallbackUri);
      let keycloakLogoutUrl;
      if (config2.KEYCLOAK_LOGOUT_URL) {
        if (config2.KEYCLOAK_LOGOUT_URL.startsWith("http")) {
          keycloakLogoutUrl = new URL(config2.KEYCLOAK_LOGOUT_URL);
        } else {
          keycloakLogoutUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_LOGOUT_URL}`);
        }
      } else {
        keycloakLogoutUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
      }
      keycloakLogoutUrl.searchParams.set("client_id", config2.KEYCLOAK_CLIENT_ID);
      keycloakLogoutUrl.searchParams.set("post_logout_redirect_uri", logoutCallbackUri);
      strapi.log.info("✅ Logout completed, initiating Keycloak logout");
      strapi.log.debug("🔍 Keycloak logout URL:", keycloakLogoutUrl.toString());
      const expectsJson = ctx.request.headers.accept?.includes("application/json");
      if (expectsJson) {
        strapi.log.debug("🔍 Returning JSON response with logout URL");
        return ctx.send({
          data: {
            logoutUrl: keycloakLogoutUrl.toString(),
            sessionDestroyed,
            tokensRevoked
          }
        });
      } else {
        strapi.log.debug("🔍 Redirecting to Keycloak logout");
        return ctx.redirect(keycloakLogoutUrl.toString());
      }
    } catch (error) {
      strapi.log.error("🔴 Logout failed:", error.message);
      strapi.log.debug("🔍 Full error:", error.stack);
      try {
        ctx.cookies.set("strapi_admin_refresh", null, {
          maxAge: 0,
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          path: "/"
        });
      } catch (cookieError) {
        strapi.log.debug("🔍 Failed to clear cookies:", cookieError.message);
      }
      const expectsJson = ctx.request.headers.accept?.includes("application/json");
      if (expectsJson) {
        return ctx.send({
          data: {
            logoutUrl: "/admin/auth/login",
            sessionDestroyed: false,
            tokensRevoked: false,
            error: error.message
          }
        });
      } else {
        const redirectUri = config?.KEYCLOAK_LOGOUT_REDIRECT_URI || "/admin/auth/login";
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
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      strapi.log.info("🔵 Logout callback received from Keycloak");
      strapi.log.debug("🔍 Query params:", ctx.query);
      const finalRedirectUri = config2.KEYCLOAK_LOGOUT_REDIRECT_URI || "/admin/auth/login";
      strapi.log.info("✅ Logout flow completed, redirecting to:", finalRedirectUri);
      return ctx.redirect(finalRedirectUri);
    } catch (error) {
      strapi.log.error("🔴 Logout callback failed:", error.message);
      return ctx.redirect("/admin/auth/login");
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
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      const redirectUri = config2.KEYCLOAK_REDIRECT_URI;
      if (!redirectUri) {
        return ctx.badRequest("KEYCLOAK_REDIRECT_URI is not configured");
      }
      const state = generateState();
      ctx.session = {
        ...ctx.session,
        oauth2State: state
      };
      const authUrl = buildAuthorizationUrl(config2, redirectUri, state);
      strapi.log.info("🔵 Generated Keycloak authorization URL.");
      return ctx.send({ authorizationUrl: authUrl.toString(), state });
    } catch (error) {
      strapi.log.error("🔴 Failed to generate authorization URL:", error.message);
      return ctx.badRequest("Failed to generate authorization URL");
    }
  }
};
const bootstrap = async ({ strapi: strapi2 }) => {
  strapi2.log.info("🚀 Strapi Keycloak Passport Plugin Bootstrapped");
  try {
    strapi2.log.info("🔍 Registering Keycloak Plugin Permissions...");
    const actions = [
      {
        section: "plugins",
        displayName: "Access Keycloak Plugin",
        uid: "access",
        pluginName: "strapi-keycloak-passport"
      },
      {
        section: "plugins",
        displayName: "View Role Mappings",
        uid: "view-role-mappings",
        pluginName: "strapi-keycloak-passport"
      },
      {
        section: "plugins",
        displayName: "Manage Role Mappings",
        uid: "manage-role-mappings",
        pluginName: "strapi-keycloak-passport"
      }
    ];
    await strapi2.admin.services.permission.actionProvider.registerMany(actions);
    strapi2.log.info("✅ Keycloak Plugin permissions successfully registered.");
  } catch (error) {
    strapi2.log.error("❌ Failed to register Keycloak Plugin permissions:", error);
  }
  await ensureDefaultRoleMapping(strapi2);
  overrideAdminRoutes(strapi2);
  strapi2.log.info("🔒 Passport Keycloak Strategy Initialized");
};
function overrideAdminRoutes(strapi2) {
  try {
    strapi2.log.info("🛠 Applying Keycloak Authentication Middleware...");
    strapi2.server.use(async (ctx, next) => {
      const requestPath = ctx.request.path;
      const requestMethod = ctx.request.method;
      if (requestPath === "/admin/login" && requestMethod === "POST") {
        await authOverrideController.login(ctx);
      } else if ((requestPath.includes("auth/reset-password") || requestPath.includes("auth/forgot-password") || requestPath.includes("auth/register")) && requestMethod === "GET") {
        return ctx.redirect("/admin/login");
      } else {
        await next();
      }
    });
    strapi2.log.info(`
      
    ╔════════════════════════════════╗
    ║      🛡️ PASSPORT APPLIED 🛡️      ║
    ╚════════════════════════════════╝
    `);
    strapi2.log.info("🚴 Admin login request rerouted to passport.");
    strapi2.log.info("📒 Registration route blocked. 🚫");
    strapi2.log.info("🕵️‍♂️ Reset password route blocked. 🚫");
  } catch (error) {
    strapi2.log.error("❌ Failed to register Keycloak Middleware:", error);
  }
}
async function ensureDefaultRoleMapping(strapi2) {
  try {
    const superAdminRole = await strapi2.db.query("admin::role").findOne({ where: { code: "strapi-super-admin" } });
    if (!superAdminRole) {
      strapi2.log.warn("⚠️ Super Admin role not found. Skipping default role mapping.");
      return;
    }
    const DEFAULT_MAPPING = {
      keycloakRole: "SUPER_ADMIN",
      strapiRole: superAdminRole.id
      // 🔹 Fetch role ID dynamically
    };
    const existingMapping = await strapi2.db.query("plugin::strapi-keycloak-passport.role-mapping").findOne({ where: { keycloakRole: DEFAULT_MAPPING.keycloakRole } });
    if (!existingMapping) {
      await strapi2.db.query("plugin::strapi-keycloak-passport.role-mapping").create({ data: DEFAULT_MAPPING });
      strapi2.log.info(`✅ Default Role Mapping Created: ${DEFAULT_MAPPING.keycloakRole} -> ${DEFAULT_MAPPING.strapiRole} (mapped to Super Admin Role)`);
    } else {
      strapi2.log.info(`✅ Default Role Mapping Already Exists: ${existingMapping.keycloakRole} -> ${existingMapping.strapiRole} (mapping to Super Admin Role)`);
    }
  } catch (error) {
    strapi2.log.error("❌ Failed to create default role mapping:", error);
  }
}
const destroy = ({ strapi: strapi2 }) => {
};
const register = ({ strapi: strapi2 }) => {
  strapi2.log.info("🔄 Registering Strapi Keycloak Passport Plugin...");
};
const config$1 = {
  default: ({ env }) => ({
    KEYCLOAK_AUTH_URL: "",
    KEYCLOAK_REALM: "",
    KEYCLOAK_CLIENT_ID: "",
    KEYCLOAK_CLIENT_SECRET: "",
    KEYCLOAK_TOKEN_URL: "",
    KEYCLOAK_USERINFO_URL: "",
    KEYCLOAK_LOGOUT_URL: "",
    KEYCLOAK_REDIRECT_URI: "",
    KEYCLOAK_LOGOUT_REDIRECT_URI: "",
    KEYCLOAK_SCOPE: "openid email profile",
    REMEMBER_ME: false,
    roleConfigs: {
      defaultRoleId: env.int("KEYCLOAK_PASSPORT_DEFAULT_ROLE_ID", 3),
      superAdmin: {
        roleId: env.int("KEYCLOAK_PASSPORT_SUPER_ADMIN_ROLE_ID", 1),
        keycloakRole: env("KEYCLOAK_PASSPORT_SUPER_ADMIN_KEYCLOAK_ROLE", "STRAPI_ADMIN")
      },
      editor: {
        roleId: env.int("KEYCLOAK_PASSPORT_ADMIN_ROLE_ID", 2),
        keycloakRole: env("KEYCLOAK_PASSPORT_ADMIN_KEYCLOAK_ROLE", "editor")
      },
      author: {
        roleId: env.int("KEYCLOAK_PASSPORT_USER_ROLE_ID", 3),
        keycloakRole: env("KEYCLOAK_PASSPORT_USER_KEYCLOAK_ROLE", "author")
      },
      excludedRoles: env.array("KEYCLOAK_PASSPORT_EXCLUDED_ROLES", [
        "uma_authorization",
        "default-roles-NCR",
        "offline_access"
      ])
    }
  }),
  validator(config2) {
    if (!config2.KEYCLOAK_AUTH_URL) {
      throw new Error("Missing KEYCLOAK_AUTH_URL in plugin config.");
    }
    if (!config2.KEYCLOAK_REALM) {
      throw new Error("Missing KEYCLOAK_REALM in plugin config.");
    }
    if (!config2.KEYCLOAK_CLIENT_ID) {
      throw new Error("Missing KEYCLOAK_CLIENT_ID in plugin config.");
    }
    if (!config2.KEYCLOAK_CLIENT_SECRET) {
      throw new Error("Missing KEYCLOAK_CLIENT_SECRET in plugin config.");
    }
  }
};
const kind = "collectionType";
const uid = "plugin::strapi-keycloak-passport.role-mapping";
const info = {
  singularName: "role-mapping",
  pluralName: "role-mappings",
  displayName: "Role Mapping",
  description: "Maps Keycloak roles to Strapi roles."
};
const attributes = {
  keycloakRole: {
    type: "string",
    minLength: 3,
    maxLength: 100,
    required: true
  },
  strapiRole: {
    type: "integer",
    required: true
  }
};
const schema = {
  kind,
  uid,
  info,
  attributes
};
const roleMapping = {
  schema
};
const contentTypes = {
  "role-mapping": roleMapping
};
const authController = {
  /**
   * Fetches all Keycloak roles and Strapi admin roles.
   *
   * @async
   * @function getRoles
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} - Object containing Keycloak roles and Strapi roles.
   * @throws {Error} If fetching roles fails.
   */
  async getRoles(ctx) {
    try {
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      strapi.log.debug("🔍 Fetching Keycloak roles...");
      const accessToken = await strapi.plugin("strapi-keycloak-passport").service("keycloakService").fetchAdminToken();
      let rolesApiUrl;
      if (config2.KEYCLOAK_AUTH_URL.includes("/realms/")) {
        const baseUrl = config2.KEYCLOAK_AUTH_URL.split("/realms/")[0];
        rolesApiUrl = `${baseUrl}/admin/realms/${config2.KEYCLOAK_REALM}/roles`;
      } else {
        rolesApiUrl = `${config2.KEYCLOAK_AUTH_URL}/admin/realms/${config2.KEYCLOAK_REALM}/roles`;
      }
      strapi.log.debug("🔍 Roles API URL:", rolesApiUrl);
      const rolesResponse = await axios.get(
        rolesApiUrl,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      strapi.log.debug("🔍 Fetched roles count:", rolesResponse.data.length);
      const excludedRoles = config2.roleConfigs?.excludedRoles || [];
      const keycloakRoles = rolesResponse.data.filter(
        (role) => !excludedRoles.includes(role.name)
      );
      strapi.log.debug("🔍 Filtered roles count:", keycloakRoles.length);
      const strapiRoles = await strapi.entityService.findMany("admin::role", {});
      strapi.log.info("✅ Successfully fetched Keycloak and Strapi roles");
      return ctx.send({ keycloakRoles, strapiRoles });
    } catch (error) {
      strapi.log.error(
        '❌ Failed to fetch Keycloak roles: Have you tried giving the role "MANAGE-REALM" and "MANAGE-USERS"?',
        error.response?.data || error.message
      );
      return ctx.badRequest("Failed to fetch Keycloak roles");
    }
  },
  /**
   * Retrieves Keycloak-to-Strapi role mappings.
   *
   * @async
   * @function getRoleMappings
   * @param {Object} ctx - Koa context.
   * @returns {Promise<Object>} - Object mapping Keycloak roles to Strapi roles.
   * @throws {Error} If retrieval fails.
   */
  async getRoleMappings(ctx) {
    try {
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      const roleConfigs = config2.roleConfigs;
      strapi.log.debug("🔍 Fetching role mappings from config...");
      const formattedMappings = {};
      for (const [key, value] of Object.entries(roleConfigs)) {
        if (key === "defaultRoleId" || key === "excludedRoles") continue;
        if (value.keycloakRole && value.roleId) {
          formattedMappings[value.keycloakRole] = value.roleId;
        }
      }
      strapi.log.debug("🔍 Role mappings:", formattedMappings);
      strapi.log.info("✅ Successfully retrieved role mappings");
      return ctx.send(formattedMappings);
    } catch (error) {
      strapi.log.error("❌ Failed to retrieve role mappings:", error.response?.data || error.message);
      return ctx.badRequest("Failed to retrieve role mappings");
    }
  },
  /**
   * Saves Keycloak-to-Strapi role mappings.
   *
   * @async
   * @function saveRoleMappings
   * @param {Object} ctx - Koa context.
   * @param {Object} ctx.request - Request object.
   * @param {Object} ctx.request.body - Request body containing role mappings.
   * @param {Object<string, number>} ctx.request.body.mappings - Object mapping Keycloak roles to Strapi roles.
   * @returns {Promise<Object>} - Confirmation message.
   * @throws {Error} If saving fails.
   */
  async saveRoleMappings(ctx) {
    try {
      strapi.log.warn("⚠️ Role mappings are now config-based and cannot be saved via API");
      strapi.log.info("ℹ️ Please update role mappings in config/plugins.js");
      return ctx.send({
        message: "Role mappings are config-based. Please update config/plugins.js to modify role mappings.",
        success: false,
        configBased: true
      });
    } catch (error) {
      strapi.log.error("❌ Failed to save role mappings:", error.response?.data || error.message);
      return ctx.badRequest("Failed to save role mappings");
    }
  }
};
const controllers = {
  authController,
  authOverrideController
};
const checkAdminPermission = (requiredPermission) => async (ctx, next) => {
  try {
    const adminUser = ctx.session.user;
    if (!adminUser) {
      return ctx.unauthorized("User is not authenticated.");
    }
    const [roleId] = adminUser.roles.map((role) => role.id);
    const adminPermissions = await strapi.admin.services.permission.findMany({
      where: {
        role: roleId,
        action: requiredPermission
      }
    });
    if (adminPermissions.length === 0) {
      return ctx.forbidden(`Access denied. Missing permission: ${requiredPermission}`);
    }
    await next();
  } catch (error) {
    strapi.log.error("🔴 Error checking admin permission:", error);
    return ctx.internalServerError("Failed to verify permissions.");
  }
};
const middlewares = {
  checkAdminPermission
};
const policies = {};
const routes = [
  // ✅ Override Admin Login with Keycloak (password grant - legacy for Keycloak < 18)
  {
    method: "POST",
    path: "/admin/login",
    handler: "authOverrideController.login",
    config: {
      auth: false
      // No auth required for login
    }
  },
  // ✅ Override Admin Logout to handle both Strapi and Keycloak logout
  {
    method: "POST",
    path: "/admin/logout",
    handler: "authOverrideController.logout",
    config: {
      auth: false
      // Allow logout even if token is invalid/expired
    }
  },
  // ✅ OAuth2 Authorization Code Flow - Initiate (Keycloak 18+)
  {
    method: "GET",
    path: "/authorize",
    handler: "authOverrideController.authorize",
    config: {
      auth: false
      // No auth required to initiate OAuth2 flow
    }
  },
  // ✅ OAuth2 Authorization Code Flow - Callback (Keycloak 18+)
  {
    method: "GET",
    path: "/callback",
    handler: "authOverrideController.callback",
    config: {
      auth: false
      // No auth required for OAuth2 callback
    }
  },
  // ✅ Get Authorization URL for OAuth2 flow (Keycloak 18+)
  {
    method: "GET",
    path: "/authorization-url",
    handler: "authOverrideController.getAuthorizationUrl",
    config: {
      auth: false
      // No auth required to get authorization URL
    }
  },
  // ✅ Get Keycloak Logout URL
  {
    method: "GET",
    path: "/logout-url",
    handler: "authOverrideController.getLogoutUrl",
    config: {
      auth: false
      // No auth required to get logout URL
    }
  },
  // ✅ Logout Callback - Receives redirect from Keycloak after logout
  {
    method: "GET",
    path: "/logout-callback",
    handler: "authOverrideController.logoutCallback",
    config: {
      auth: false
      // No auth required for logout callback
    }
  },
  // ✅ Get Keycloak Roles (requires authentication)
  {
    method: "GET",
    path: "/keycloak-roles",
    handler: "authController.getRoles",
    config: {
      auth: false,
      // Auth handled by admin session
      policies: []
    }
  },
  // ✅ Get Role Mappings (config-based, read-only)
  {
    method: "GET",
    path: "/get-keycloak-role-mappings",
    handler: "authController.getRoleMappings",
    config: {
      auth: false,
      // Auth handled by admin session
      policies: []
    }
  },
  // ✅ Save Role Mappings (returns config-based message)
  {
    method: "POST",
    path: "/save-keycloak-role-mappings",
    handler: "authController.saveRoleMappings",
    config: {
      auth: false,
      // Auth handled by admin session
      policies: []
    }
  }
];
const adminUserService = ({ strapi: strapi2 }) => ({
  /**
   * Finds or creates an admin user in Strapi and assigns the correct role.
   *
   * @async
   * @function findOrCreate
   * @param {Object} userInfo - The user data from Keycloak.
   * @param {string} userInfo.email - User's email.
   * @param {string} [userInfo.preferred_username] - Preferred username.
   * @param {string} [userInfo.given_name] - First name.
   * @param {string} [userInfo.family_name] - Last name.
   * @param {string} userInfo.sub - Unique Keycloak user ID.
   * @returns {Promise<Object>} The created or updated Strapi admin user.
   */
  async findOrCreate(userInfo) {
    try {
      const email = userInfo.email;
      const username = userInfo.preferred_username || "";
      const firstname = userInfo.given_name || "";
      const lastname = userInfo.family_name || "";
      const keycloakUserId = userInfo.sub;
      strapi2.log.debug("🔍 User info for findOrCreate:", {
        email,
        username,
        firstname,
        lastname,
        keycloakUserId
      });
      let [adminUser] = await strapi2.entityService.findMany("admin::user", {
        filters: { email },
        populate: { roles: true },
        limit: 1
      });
      strapi2.log.debug("🔍 Existing admin user found:", {
        exists: !!adminUser,
        id: adminUser?.id,
        currentRoles: adminUser?.roles
      });
      const config2 = strapi2.config.get("plugin::strapi-keycloak-passport");
      const roleConfigs = config2.roleConfigs;
      const DEFAULT_ROLE_ID = roleConfigs.defaultRoleId;
      let appliedRoles = /* @__PURE__ */ new Set();
      try {
        strapi2.log.debug("🔍 Fetching Keycloak roles for user:", keycloakUserId);
        const keycloakRoles = await fetchKeycloakUserRoles(keycloakUserId, strapi2);
        strapi2.log.debug("🔍 Keycloak roles received:", keycloakRoles);
        strapi2.log.debug("🔍 Role configurations:", roleConfigs);
        const excludedRoles = roleConfigs.excludedRoles || [];
        const filteredRoles = keycloakRoles.filter((role) => !excludedRoles.includes(role));
        strapi2.log.debug("🔍 Filtered roles (excluded removed):", filteredRoles);
        filteredRoles.forEach((keycloakRole) => {
          for (const [configKey, roleMapping2] of Object.entries(roleConfigs)) {
            if (configKey === "defaultRoleId" || configKey === "excludedRoles") continue;
            if (roleMapping2.keycloakRole === keycloakRole) {
              appliedRoles.add(roleMapping2.roleId);
              strapi2.log.debug(`🔍 Mapped ${keycloakRole} -> Strapi role ${roleMapping2.roleId} (${configKey})`);
              break;
            }
          }
        });
        if (appliedRoles.size === 0) {
          strapi2.log.debug("🔍 No matching role mappings found, will use default role");
        }
      } catch (error) {
        strapi2.log.error("❌ Failed to fetch user roles from Keycloak:", error.response?.data || error.message);
      }
      const userRoles = appliedRoles.size ? Array.from(appliedRoles) : [DEFAULT_ROLE_ID];
      strapi2.log.debug("🔍 Final user roles:", { roles: userRoles, usingDefault: appliedRoles.size === 0 });
      if (!adminUser) {
        strapi2.log.debug("🔍 Creating new admin user with data:", {
          email,
          firstname,
          lastname,
          username,
          roles: userRoles
        });
        adminUser = await strapi2.entityService.create("admin::user", {
          data: {
            email,
            firstname,
            lastname,
            username,
            isActive: true,
            roles: userRoles
          }
        });
        strapi2.log.info(`✅ Created new admin user: ${email}`);
        strapi2.log.debug("🔍 Created user result:", adminUser);
      } else if (JSON.stringify(adminUser.roles) !== JSON.stringify(userRoles)) {
        strapi2.log.debug("🔍 Updating user roles:", {
          documentId: adminUser.documentId,
          oldRoles: adminUser.roles,
          newRoles: userRoles
        });
        adminUser = await strapi2.documents("admin::user").update({
          documentId: adminUser.documentId,
          data: {
            firstname,
            lastname,
            roles: userRoles
          }
        });
        strapi2.log.info(`✅ Updated admin user roles: ${email}`);
        strapi2.log.debug("🔍 Updated user result:", adminUser);
      } else {
        strapi2.log.debug("🔍 User exists and roles unchanged, no update needed");
      }
      strapi2.log.debug("🔍 Returning admin user:", {
        id: adminUser?.id,
        email: adminUser?.email,
        roles: adminUser?.roles
      });
      return adminUser;
    } catch (error) {
      strapi2.log.error("❌ Failed to create/update user:", error.message);
      throw new Error("Failed to create/update user.");
    }
  }
});
async function fetchKeycloakUserRoles(keycloakUserId, strapi2) {
  if (!keycloakUserId) throw new Error("❌ Keycloak user ID is missing!");
  const config2 = strapi2.config.get("plugin::strapi-keycloak-passport");
  try {
    strapi2.log.debug("🔍 Fetching Keycloak admin token for role retrieval...");
    const accessToken = await strapi2.plugin("strapi-keycloak-passport").service("keycloakService").fetchAdminToken();
    strapi2.log.debug("🔍 Admin token retrieved for roles API");
    let rolesApiUrl;
    if (config2.KEYCLOAK_AUTH_URL.includes("/realms/")) {
      const baseUrl = config2.KEYCLOAK_AUTH_URL.split("/realms/")[0];
      rolesApiUrl = `${baseUrl}/admin/realms/${config2.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`;
    } else {
      rolesApiUrl = `${config2.KEYCLOAK_AUTH_URL}/admin/realms/${config2.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`;
    }
    strapi2.log.debug("🔍 Fetching user roles from:", rolesApiUrl);
    const rolesResponse = await axios.get(
      rolesApiUrl,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const roleNames = rolesResponse.data.map((role) => role.name);
    strapi2.log.debug("🔍 User roles from Keycloak:", roleNames);
    return roleNames;
  } catch (error) {
    strapi2.log.error("❌ Failed to fetch Keycloak user roles:", error.response?.data || error.message);
    throw new Error("Failed to fetch Keycloak user roles.");
  }
}
const roleMappingService = ({ strapi: strapi2 }) => ({
  /**
   * Saves the given role mappings to the database.
   *
   * @async
   * @function saveMappings
   * @param {Object<string, number>} mappings - The role mappings.
   * @returns {Promise<void>} - Resolves when role mappings are saved.
   */
  async saveMappings(mappings) {
    try {
      await strapi2.db.query("plugin::strapi-keycloak-passport.role-mapping").deleteMany({
        where: {
          id: {
            $notNull: true
          }
        }
      });
      for (const [keycloakRole, strapiRole] of Object.entries(mappings)) {
        await strapi2.entityService.create("plugin::strapi-keycloak-passport.role-mapping", {
          data: { keycloakRole, strapiRole }
        });
      }
      strapi2.log.info("✅ Role mappings saved successfully.");
    } catch (error) {
      strapi2.log.error("❌ Failed to save role mappings:", error);
      throw new Error("Failed to save role mappings.");
    }
  },
  /**
   * Retrieves all role mappings from the database.
   *
   * @async
   * @function getMappings
   * @returns {Promise<RoleMapping[]>} - List of role mappings.
   */
  async getMappings() {
    try {
      const roleMappings = await strapi2.entityService.findMany("plugin::strapi-keycloak-passport.role-mapping", {});
      return roleMappings;
    } catch (error) {
      strapi2.log.error("❌ Failed to retrieve role mappings:", error);
      throw new Error("Failed to retrieve role mappings.");
    }
  }
});
const keycloakService = ({ strapi: strapi2 }) => ({
  /**
   * Fetches an admin access token from Keycloak.
   *
   * @async
   * @function fetchAdminToken
   * @returns {Promise<string>} The Keycloak access token.
   * @throws {Error} If authentication fails.
   */
  async fetchAdminToken() {
    const config2 = strapi2.config.get("plugin::strapi-keycloak-passport");
    try {
      let tokenUrl;
      if (config2.KEYCLOAK_TOKEN_URL) {
        tokenUrl = config2.KEYCLOAK_TOKEN_URL.startsWith("http") ? config2.KEYCLOAK_TOKEN_URL : `${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_TOKEN_URL}`;
      } else {
        tokenUrl = `${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/token`;
      }
      strapi2.log.debug("🔍 Fetching admin token from:", tokenUrl);
      const tokenResponse = await axios.post(
        tokenUrl,
        new URLSearchParams({
          client_id: config2.KEYCLOAK_CLIENT_ID,
          client_secret: config2.KEYCLOAK_CLIENT_SECRET,
          grant_type: "client_credentials",
          scope: config2.KEYCLOAK_SCOPE || "openid email profile"
        }).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const accessToken = tokenResponse.data?.access_token;
      if (!accessToken) {
        throw new Error("❌ Keycloak returned an empty access token");
      }
      strapi2.log.info("✅ Successfully fetched Keycloak admin token.");
      return accessToken;
    } catch (error) {
      strapi2.log.error("❌ Keycloak Admin Token Fetch Error:", {
        status: error.response?.status || "Unknown",
        statusText: error.response?.statusText,
        url: error.config?.url,
        message: error.response?.data || error.message,
        hasClientSecret: !!config2.KEYCLOAK_CLIENT_SECRET,
        clientId: config2.KEYCLOAK_CLIENT_ID
      });
      throw new Error("Failed to fetch Keycloak admin token");
    }
  }
});
const services = {
  adminUserService,
  roleMappingService,
  keycloakService
};
const index = {
  bootstrap,
  destroy,
  register,
  config: config$1,
  controllers,
  contentTypes,
  middlewares,
  policies,
  routes,
  services
};
export {
  index as default
};
