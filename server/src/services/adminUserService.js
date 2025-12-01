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

      strapi.log.debug('🔍 User info for findOrCreate:', {
        email,
        username,
        firstname,
        lastname,
        keycloakUserId
      });

      /** @type {Object|null} */
      let [adminUser] = await strapi.entityService.findMany('admin::user', {
        filters: { email },
        populate: { roles: true },
        limit: 1,
      });
      
      strapi.log.debug('🔍 Existing admin user found:', {
        exists: !!adminUser,
        id: adminUser?.id,
        currentRoles: adminUser?.roles
      });

      /** @type {Object} */
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const roleConfigs = config.roleConfigs;

      /** @type {number} */
      const DEFAULT_ROLE_ID = roleConfigs.defaultRoleId;

      /** @type {Set<number>} */
      let appliedRoles = new Set();

      try {
        // 🔥 Fetch user roles from Keycloak
        strapi.log.debug('🔍 Fetching Keycloak roles for user:', keycloakUserId);
        const keycloakRoles = await fetchKeycloakUserRoles(keycloakUserId, strapi);
        strapi.log.debug('🔍 Keycloak roles received:', keycloakRoles);

        // 🔄 Map Keycloak roles to Strapi roles using roleConfigs
        strapi.log.debug('🔍 Role configurations:', roleConfigs);
        
        // Filter out excluded roles
        const excludedRoles = roleConfigs.excludedRoles || [];
        const filteredRoles = keycloakRoles.filter(role => !excludedRoles.includes(role));
        strapi.log.debug('🔍 Filtered roles (excluded removed):', filteredRoles);

        // Map Keycloak roles to Strapi role IDs
        filteredRoles.forEach((keycloakRole) => {
          // Check each role mapping config (superAdmin, editor, author, etc.)
          for (const [configKey, roleMapping] of Object.entries(roleConfigs)) {
            // Skip non-mapping config entries
            if (configKey === 'defaultRoleId' || configKey === 'excludedRoles') continue;
            
            if (roleMapping.keycloakRole === keycloakRole) {
              appliedRoles.add(roleMapping.roleId);
              strapi.log.debug(`🔍 Mapped ${keycloakRole} -> Strapi role ${roleMapping.roleId} (${configKey})`);
              break;
            }
          }
        });
        
        if (appliedRoles.size === 0) {
          strapi.log.debug('🔍 No matching role mappings found, will use default role');
        }
      } catch (error) {
        strapi.log.error('❌ Failed to fetch user roles from Keycloak:', error.response?.data || error.message);
      }

      /** @type {number[]} */
      const userRoles = appliedRoles.size ? Array.from(appliedRoles) : [DEFAULT_ROLE_ID];
      strapi.log.debug('🔍 Final user roles:', { roles: userRoles, usingDefault: appliedRoles.size === 0 });

      // ✅ Efficiently create or update user only when needed
      if (!adminUser) {
        strapi.log.debug('🔍 Creating new admin user with data:', {
          email,
          firstname,
          lastname,
          username,
          roles: userRoles
        });
        adminUser = await strapi.entityService.create('admin::user', {
          data: {
            email,
            firstname,
            lastname,
            username,
            isActive: true,
            roles: userRoles,
          },
        });
        strapi.log.info(`✅ Created new admin user: ${email}`);
        strapi.log.debug('🔍 Created user result:', adminUser);
      } else if (JSON.stringify(adminUser.roles) !== JSON.stringify(userRoles)) {
        strapi.log.debug('🔍 Updating user roles:', {
          documentId: adminUser.documentId,
          oldRoles: adminUser.roles,
          newRoles: userRoles
        });
        adminUser = await strapi.documents('admin::user').update({
          documentId: adminUser.documentId,
          data: {
            firstname,
            lastname,
            roles: userRoles,
          },
        });
        strapi.log.info(`✅ Updated admin user roles: ${email}`);
        strapi.log.debug('🔍 Updated user result:', adminUser);
      } else {
        strapi.log.debug('🔍 User exists and roles unchanged, no update needed');
      }

      strapi.log.debug('🔍 Returning admin user:', {
        id: adminUser?.id,
        email: adminUser?.email,
        roles: adminUser?.roles
      });
      return adminUser;
    } catch (error) {
      strapi.log.error('❌ Failed to create/update user:', error.message);
      throw new Error('Failed to create/update user.');
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

  try {
    // 🔑 Fetch Keycloak Admin Token from service
    strapi.log.debug('🔍 Fetching Keycloak admin token for role retrieval...');
    const accessToken = await strapi
      .plugin('strapi-keycloak-passport')
      .service('keycloakService')
      .fetchAdminToken();
    strapi.log.debug('🔍 Admin token retrieved for roles API');

    // Construct roles API URL - support both full URLs and path-based config
    let rolesApiUrl;
    if (config.KEYCLOAK_AUTH_URL.includes('/realms/')) {
      // Full URL format: extract base URL
      const baseUrl = config.KEYCLOAK_AUTH_URL.split('/realms/')[0];
      rolesApiUrl = `${baseUrl}/admin/realms/${config.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`;
    } else {
      // Base URL format
      rolesApiUrl = `${config.KEYCLOAK_AUTH_URL}/admin/realms/${config.KEYCLOAK_REALM}/users/${keycloakUserId}/role-mappings/realm`;
    }
    
    strapi.log.debug('🔍 Fetching user roles from:', rolesApiUrl);
    const rolesResponse = await axios.get(
      rolesApiUrl,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    
    const roleNames = rolesResponse.data.map(role => role.name);
    strapi.log.debug('🔍 User roles from Keycloak:', roleNames);
    return roleNames;
  } catch (error) {
    strapi.log.error('❌ Failed to fetch Keycloak user roles:', error.response?.data || error.message);
    throw new Error('Failed to fetch Keycloak user roles.');
  }
}

export default adminUserService;