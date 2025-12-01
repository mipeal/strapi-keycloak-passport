import checkAdminPermission from '../middlewares/checkAdminPermission';

/**
 * Strapi Keycloak Passport Plugin Routes (Strapi v5)
 *
 * @module Routes
 */
const routes = [
  // ✅ Override Admin Login with Keycloak (password grant - legacy for Keycloak < 18)
  {
    method: 'POST',
    path: '/admin/login',
    handler: 'authOverrideController.login',
    config: {
      auth: false, // No auth required for login
    },
  },

  // ✅ Override Admin Logout to handle both Strapi and Keycloak logout
  {
    method: 'POST',
    path: '/admin/logout',
    handler: 'authOverrideController.logout',
    config: {
      auth: false, // Allow logout even if token is invalid/expired
    },
  },

  // ✅ OAuth2 Authorization Code Flow - Initiate (Keycloak 18+)
  {
    method: 'GET',
    path: '/authorize',
    handler: 'authOverrideController.authorize',
    config: {
      auth: false, // No auth required to initiate OAuth2 flow
    },
  },

  // ✅ OAuth2 Authorization Code Flow - Callback (Keycloak 18+)
  {
    method: 'GET',
    path: '/callback',
    handler: 'authOverrideController.callback',
    config: {
      auth: false, // No auth required for OAuth2 callback
    },
  },

  // ✅ Get Authorization URL for OAuth2 flow (Keycloak 18+)
  {
    method: 'GET',
    path: '/authorization-url',
    handler: 'authOverrideController.getAuthorizationUrl',
    config: {
      auth: false, // No auth required to get authorization URL
    },
  },

  // ✅ Get Keycloak Logout URL
  {
    method: 'GET',
    path: '/logout-url',
    handler: 'authOverrideController.getLogoutUrl',
    config: {
      auth: false, // No auth required to get logout URL
    },
  },

  // ✅ Logout Callback - Receives redirect from Keycloak after logout
  {
    method: 'GET',
    path: '/logout-callback',
    handler: 'authOverrideController.logoutCallback',
    config: {
      auth: false, // No auth required for logout callback
    },
  },

  // ✅ Get Keycloak Roles (Admin Permission Required)
  {
    method: 'GET',
    path: '/keycloak-roles',
    handler: 'authController.getRoles',
    config: {
      auth: false,
      policies: [],
      middlewares: [checkAdminPermission('plugin::strapi-keycloak-passport.access')],
    },
  },

  // ✅ Get Role Mappings (Admin Permission Required)
  {
    method: 'GET',
    path: '/get-keycloak-role-mappings',
    handler: 'authController.getRoleMappings',
    config: {
      auth: false, // ✅ Required for admin data access
      policies: [],
      middlewares: [checkAdminPermission('plugin::strapi-keycloak-passport.view-role-mappings')],
    },
  },

  // ✅ Save Role Mappings (Requires Manage Permission)
  {
    method: 'POST',
    path: '/save-keycloak-role-mappings',
    handler: 'authController.saveRoleMappings',
    config: {
      auth: false, // ✅ Ensures only admins can perform this action
      policies: [],
      middlewares: [checkAdminPermission('plugin::strapi-keycloak-passport.manage-role-mappings')],
    },
  },
];

export default routes;