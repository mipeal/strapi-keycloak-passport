export default {
  default: ({ env }) => {
    // Parse excluded roles with detailed logging
    const excludedRolesRaw = env('KEYCLOAK_PASSPORT_EXCLUDED_ROLES');
    const excludedRoles = excludedRolesRaw 
      ? excludedRolesRaw.split(',').map(r => r.trim())
      : [
          'uma_authorization',
          'default-roles-ncr',
          'offline_access',
        ];

    console.log('🔍 [CONFIG] Excluded roles from env:', excludedRolesRaw);
    console.log('🔍 [CONFIG] Parsed excluded roles:', excludedRoles);

    return {
      KEYCLOAK_AUTH_URL: '',
      KEYCLOAK_REALM: '',
      KEYCLOAK_CLIENT_ID: '',
      KEYCLOAK_CLIENT_SECRET: '',
      KEYCLOAK_TOKEN_URL: '',
      KEYCLOAK_USERINFO_URL: '',
      KEYCLOAK_LOGOUT_URL: '',
      KEYCLOAK_REDIRECT_URI: '',
      KEYCLOAK_LOGOUT_REDIRECT_URI: '',
      KEYCLOAK_SCOPE: 'openid email profile',
      REMEMBER_ME: false,
      roleConfigs: {
        defaultRoleId: env.int('KEYCLOAK_PASSPORT_DEFAULT_ROLE_ID', 3),
        superAdmin: {
          roleId: env.int('KEYCLOAK_PASSPORT_SUPER_ADMIN_ROLE_ID', 1),
          keycloakRole: env('KEYCLOAK_PASSPORT_SUPER_ADMIN_KEYCLOAK_ROLE', 'STRAPI_ADMIN'),
        },
        editor: {
          roleId: env.int('KEYCLOAK_PASSPORT_ADMIN_ROLE_ID', 2),
          keycloakRole: env('KEYCLOAK_PASSPORT_ADMIN_KEYCLOAK_ROLE', 'editor'),
        },
        author: {
          roleId: env.int('KEYCLOAK_PASSPORT_USER_ROLE_ID', 3),
          keycloakRole: env('KEYCLOAK_PASSPORT_USER_KEYCLOAK_ROLE', 'author'),
        },
        excludedRoles,
      },
    };
  },
  validator(config) {
    if (!config.KEYCLOAK_AUTH_URL) {
      throw new Error('Missing KEYCLOAK_AUTH_URL in plugin config.');
    }
    if (!config.KEYCLOAK_REALM) {
      throw new Error('Missing KEYCLOAK_REALM in plugin config.');
    }
    if (!config.KEYCLOAK_CLIENT_ID) {
      throw new Error('Missing KEYCLOAK_CLIENT_ID in plugin config.');
    }
    if (!config.KEYCLOAK_CLIENT_SECRET) {
      throw new Error('Missing KEYCLOAK_CLIENT_SECRET in plugin config.');
    }
  },
};