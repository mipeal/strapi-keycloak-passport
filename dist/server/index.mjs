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
      if (!email || !password) {
        return ctx.badRequest("Missing email or password");
      }
      const config2 = strapi.config.get("plugin::strapi-keycloak-passport");
      strapi.log.info(`🔵 Authenticating ${email} via Keycloak Passport...`);
      const tokenResponse = await axios.post(
        `${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_TOKEN_URL}`,
        new URLSearchParams({
          client_id: config2.KEYCLOAK_CLIENT_ID,
          client_secret: config2.KEYCLOAK_CLIENT_SECRET,
          username: email,
          password,
          grant_type: "password"
        }).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      const access_token = tokenResponse.data.access_token;
      strapi.log.info(`✅ ${email} successfully authenticated via Keycloak.`);
      const userInfoResponse = await axios.get(
        `${config2.KEYCLOAK_AUTH_URL}${config2.KEYCLOAK_USERINFO_URL}`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
      const userInfo = userInfoResponse.data;
      const adminUser = await strapi.service("plugin::strapi-keycloak-passport.adminUserService").findOrCreate(userInfo);
      const jwt = await strapi.admin.services.token.createJwtToken(adminUser);
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
            updatedAt: adminUser.updatedAt
          }
        }
      });
    } catch (error) {
      strapi.log.error(
        `🔴 Authentication Failed for ${ctx.request.body?.email || "unknown user"}:`,
        error.response?.data || error.message
      );
      return ctx.badRequest("Invalid credentials", {
        error: {
          status: error?.status ?? 400,
          name: error?.name ?? "ApplicationError",
          message: error?.message ?? "Invalid credentials",
          details: error?.details ?? {}
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
      const jwt = await strapi.admin.services.token.createJwtToken(adminUser);
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
      const logoutUrl = new URL(`${config2.KEYCLOAK_AUTH_URL}/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/logout`);
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
const config = {
  default: {
    KEYCLOAK_AUTH_URL: "",
    KEYCLOAK_REALM: "",
    KEYCLOAK_CLIENT_ID: "",
    KEYCLOAK_CLIENT_SECRET: "",
    KEYCLOAK_TOKEN_URL: "",
    KEYCLOAK_USERINFO_URL: "",
    KEYCLOAK_REDIRECT_URI: "",
    KEYCLOAK_LOGOUT_REDIRECT_URI: "",
    roleConfigs: {
      defaultRoleId: 5,
      excludedRoles: []
    }
  },
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
      const accessToken = await strapi.plugin("strapi-keycloak-passport").service("keycloakService").fetchAdminToken();
      const rolesResponse = await axios.get(
        `${config2.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config2.KEYCLOAK_REALM}/roles`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      const keycloakRoles = rolesResponse.data.filter(
        (role) => !config2.roleConfigs.excludedRoles.includes(role.name)
      );
      const strapiRoles = await strapi.entityService.findMany("admin::role", {});
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
      const mappings = await strapi.service("plugin::strapi-keycloak-passport.roleMappingService").getMappings();
      const formattedMappings = mappings.reduce((acc, mapping) => {
        acc[mapping.keycloakRole] = mapping.strapiRole;
        return acc;
      }, {});
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
      const { mappings } = ctx.request.body;
      await strapi.plugin("strapi-keycloak-passport").service("roleMappingService").saveMappings(mappings);
      return ctx.send({ message: "Mappings saved successfully." });
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
  // ✅ Get Keycloak Roles (Admin Permission Required)
  {
    method: "GET",
    path: "/keycloak-roles",
    handler: "authController.getRoles",
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission("plugin::strapi-keycloak-passport.access")]
    }
  },
  // ✅ Get Role Mappings (Admin Permission Required)
  {
    method: "GET",
    path: "/get-keycloak-role-mappings",
    handler: "authController.getRoleMappings",
    config: {
      auth: false,
      // ✅ Required for admin data access
      policies: [],
      middlewares: [checkAdminPermission("plugin::strapi-keycloak-passport.view-role-mappings")]
    }
  },
  // ✅ Save Role Mappings (Requires Manage Permission)
  {
    method: "POST",
    path: "/save-keycloak-role-mappings",
    handler: "authController.saveRoleMappings",
    config: {
      auth: false,
      // ✅ Ensures only admins can perform this action
      policies: [],
      middlewares: [checkAdminPermission("plugin::strapi-keycloak-passport.manage-role-mappings")]
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
      const [adminUser] = await strapi2.entityService.findMany("admin::user", {
        filters: { email },
        populate: { roles: true },
        limit: 1
      });
      const roleMappings = await strapi2.service("plugin::strapi-keycloak-passport.roleMappingService").getMappings();
      const DEFAULT_ROLE_ID = strapi2.config.get("plugin::strapi-keycloak-passport").roleConfigs.defaultRoleId;
      let appliedRoles = /* @__PURE__ */ new Set();
      try {
        const keycloakRoles = await fetchKeycloakUserRoles(keycloakUserId, strapi2);
        keycloakRoles.forEach((role) => {
          const mappedRole = roleMappings.find((mapped) => mapped.keycloakRole === role);
          if (mappedRole) appliedRoles.add(mappedRole.strapiRole);
        });
      } catch (error) {
        strapi2.log.error("❌ Failed to fetch user roles from Keycloak:", error.response?.data || error.message);
      }
      const userRoles = appliedRoles.size ? Array.from(appliedRoles) : [DEFAULT_ROLE_ID];
      if (!adminUser) {
        await strapi2.entityService.create("admin::user", {
          data: {
            email,
            firstname,
            lastname,
            username,
            isActive: true,
            roles: userRoles
          }
        });
      }
      if (JSON.stringify(adminUser.roles) !== JSON.stringify(userRoles)) {
        await strapi2.documents("admin::user").update({
          documentId: adminUser.documentId,
          data: {
            firstname,
            lastname,
            roles: userRoles
          }
        });
      }
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
    const accessToken = await strapi2.plugin("strapi-keycloak-passport").service("keycloakService").fetchAdminToken();
    const rolesResponse = await axios.get(
      `${config2.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config2.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    return rolesResponse.data.map((role) => role.name);
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
      const tokenResponse = await axios.post(
        `${config2.KEYCLOAK_AUTH_URL}/auth/realms/${config2.KEYCLOAK_REALM}/protocol/openid-connect/token`,
        new URLSearchParams({
          client_id: config2.KEYCLOAK_CLIENT_ID,
          client_secret: config2.KEYCLOAK_CLIENT_SECRET,
          grant_type: "client_credentials"
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
        message: error.response?.data || error.message
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
  config,
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
