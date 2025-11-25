import axios from 'axios';

/**
 * @module AdminUserService
 * @description Handles Keycloak authentication and maps user roles in Strapi.
 * @param {Object} strapi - Strapi instance.
 * @returns {Object} - Service methods.
 */
const adminUserService = ({ strapi }) => ({
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
    const config = strapi.config.get('plugin::strapi-keycloak-passport');
    const isDebugMode = config?.debug === true;

    try {
      /** @type {string} */
      const email = userInfo.email;
      /** @type {string} */
      const username = userInfo.preferred_username || '';
      /** @type {string} */
      const firstname = userInfo.given_name || '';
      /** @type {string} */
      const lastname = userInfo.family_name || '';
      /** @type {string} */
      const keycloakUserId = userInfo.sub;

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Finding or creating admin user:', {
          email,
          username,
          firstname,
          lastname,
          keycloakUserId,
        });
      }

      /** @type {Object|null} */
      const [adminUser] = await strapi.entityService.findMany('admin::user', {
        filters: { email },
        populate: { roles: true },
        limit: 1,
      });

      /** @type {Object<string, number>} */
      const roleMappings = await strapi
        .service('plugin::strapi-keycloak-passport.roleMappingService')
        .getMappings();

      /** @type {number} */
      const DEFAULT_ROLE_ID = strapi
        .config
        .get('plugin::strapi-keycloak-passport')
        .roleConfigs
        .defaultRoleId;

      /** @type {Set<number>} */
      let appliedRoles = new Set();

      try {
        // 🔥 Fetch user roles from Keycloak
        const keycloakRoles = await fetchKeycloakUserRoles(keycloakUserId, strapi);

        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Keycloak roles for user:', {
            keycloakUserId,
            keycloakRoles,
            availableMappings: roleMappings,
          });
        }

        // 🔄 Map Keycloak roles to Strapi roles
        keycloakRoles.forEach((role) => {
          const mappedRole = roleMappings.find(mapped => mapped.keycloakRole === role);
          if (mappedRole) appliedRoles.add(mappedRole.strapiRole);
        });

        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Applied Strapi roles:', {
            appliedRoles: Array.from(appliedRoles),
            defaultRoleId: DEFAULT_ROLE_ID,
          });
        }
      } catch (error) {
        strapi.log.error('❌ Failed to fetch user roles from Keycloak:', error.response?.data || error.message);

        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Keycloak role fetch error details:', {
            errorMessage: error.message,
            errorStack: error.stack,
            responseStatus: error.response?.status,
            responseData: error.response?.data,
            keycloakUserId,
          });
        }
      }

      /** @type {number[]} */
      const userRoles = appliedRoles.size ? Array.from(appliedRoles) : [DEFAULT_ROLE_ID];

      // ✅ Efficiently create or update user only when needed
      if (!adminUser) {
        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Creating new admin user:', {
            email,
            firstname,
            lastname,
            username,
            roles: userRoles,
          });
        }

        await strapi.entityService.create('admin::user', {
          data: {
            email,
            firstname,
            lastname,
            username,
            isActive: true,
            roles: userRoles,
          },
        });
      }

      if (JSON.stringify(adminUser.roles) !== JSON.stringify(userRoles)) {
        if (isDebugMode) {
          strapi.log.debug('🔍 Debug - Updating admin user roles:', {
            email,
            previousRoles: adminUser.roles,
            newRoles: userRoles,
          });
        }

        await strapi.documents('admin::user').update({
          documentId: adminUser.documentId,
          data: {
            firstname,
            lastname,
            roles: userRoles,
          },
        });
      }

      return adminUser;
    } catch (error) {
      strapi.log.error('❌ Failed to create/update user:', error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - User creation/update error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          userInfo: {
            email: userInfo.email,
            sub: userInfo.sub,
            preferredUsername: userInfo.preferred_username,
          },
        });
      }

      throw new Error(isDebugMode ? `Failed to create/update user: ${error.message}` : 'Failed to create/update user.');
    }
  },
});

/**
 * Fetches user roles from Keycloak.
 *
 * @async
 * @function fetchKeycloakUserRoles
 * @param {string} keycloakUserId - The Keycloak user ID.
 * @param {Object} strapi - Strapi instance.
 * @returns {Promise<string[]>} Array of Keycloak role names.
 * @throws {Error} If request fails or user ID is invalid.
 */
async function fetchKeycloakUserRoles(keycloakUserId, strapi) {
  if (!keycloakUserId) throw new Error('❌ Keycloak user ID is missing!');

  const config = strapi.config.get('plugin::strapi-keycloak-passport');
  const isDebugMode = config?.debug === true;

  try {
    // 🔑 Fetch Keycloak Admin Token from service
    const accessToken = await strapi
      .plugin('strapi-keycloak-passport')
      .service('keycloakService')
      .fetchAdminToken();

    const rolesEndpoint = `${config.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`;

    if (isDebugMode) {
      strapi.log.debug('🔍 Debug - Fetching user roles from Keycloak:', {
        keycloakUserId,
        rolesEndpoint,
      });
    }

    // 🔍 Fetch User Roles
    const rolesResponse = await axios.get(
      rolesEndpoint,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const roles = rolesResponse.data.map(role => role.name);

    if (isDebugMode) {
      strapi.log.debug('🔍 Debug - Fetched Keycloak user roles:', {
        keycloakUserId,
        roles,
      });
    }

    return roles;
  } catch (error) {
    strapi.log.error('❌ Failed to fetch Keycloak user roles:', error.response?.data || error.message);

    if (isDebugMode) {
      strapi.log.debug('🔍 Debug - Keycloak user roles fetch error details:', {
        errorMessage: error.message,
        errorStack: error.stack,
        responseStatus: error.response?.status,
        responseData: error.response?.data,
        keycloakUserId,
        rolesEndpoint: `${config.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`,
      });
    }

    throw new Error(isDebugMode ? `Failed to fetch Keycloak user roles: ${error.response?.data?.error_description || error.message}` : 'Failed to fetch Keycloak user roles.');
  }
}

export default adminUserService;