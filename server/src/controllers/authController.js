'use strict';

import axios from 'axios';

/**
 * @module AuthController
 * @description Handles Keycloak authentication and role management.
 */
export default {
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
      const config = strapi.config.get('plugin::strapi-keycloak-passport');

      strapi.log.debug('🔍 Fetching Keycloak roles...');

      // 🔑 Get Admin Token
      const accessToken = await strapi
        .plugin('strapi-keycloak-passport')
        .service('keycloakService')
        .fetchAdminToken();

      // 🔍 Construct roles API URL - support both full URLs and path-based config
      let rolesApiUrl;
      if (config.KEYCLOAK_AUTH_URL.includes('/realms/')) {
        // Full URL format: extract base URL
        const baseUrl = config.KEYCLOAK_AUTH_URL.split('/realms/')[0];
        rolesApiUrl = `${baseUrl}/admin/realms/${config.KEYCLOAK_REALM}/roles`;
      } else {
        // Base URL format
        rolesApiUrl = `${config.KEYCLOAK_AUTH_URL}/admin/realms/${config.KEYCLOAK_REALM}/roles`;
      }

      strapi.log.debug('🔍 Roles API URL:', rolesApiUrl);

      // 🔍 Fetch Keycloak Roles using Admin Token
      const rolesResponse = await axios.get(
        rolesApiUrl,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      strapi.log.debug('🔍 Fetched roles count:', rolesResponse.data.length);

      /** @type {Object[]} */
      const excludedRoles = config.roleConfigs?.excludedRoles || [];
      strapi.log.debug('🔍 [getRoles] Excluded roles configuration:', excludedRoles);
      strapi.log.debug('🔍 [getRoles] Raw role objects from Keycloak:', rolesResponse.data.map(r => ({ name: r.name, id: r.id })));
      
      const keycloakRoles = rolesResponse.data.filter(role => {
        const isExcluded = excludedRoles.includes(role.name);
        if (isExcluded) {
          strapi.log.debug(`🚫 [getRoles] Excluding role: ${role.name}`);
        }
        return !isExcluded;
      });

      strapi.log.debug('🔍 Filtered roles count:', keycloakRoles.length);

      /** @type {Object[]} */
      const strapiRoles = await strapi.entityService.findMany('admin::role', {});

      strapi.log.info('✅ Successfully fetched Keycloak and Strapi roles');
      return ctx.send({ keycloakRoles, strapiRoles });
    } catch (error) {
      strapi.log.error(
        '❌ Failed to fetch Keycloak roles: Have you tried giving the role "MANAGE-REALM" and "MANAGE-USERS"?',
        error.response?.data || error.message
      );
      return ctx.badRequest('Failed to fetch Keycloak roles');
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
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const roleConfigs = config.roleConfigs;

      strapi.log.debug('🔍 Fetching role mappings from config...');

      // Convert config-based role mappings to object format
      /** @type {Object} */
      const formattedMappings = {};

      // Iterate through roleConfigs and extract mappings
      for (const [key, value] of Object.entries(roleConfigs)) {
        // Skip non-mapping config entries
        if (key === 'defaultRoleId' || key === 'excludedRoles') continue;
        
        if (value.keycloakRole && value.roleId) {
          formattedMappings[value.keycloakRole] = value.roleId;
        }
      }

      strapi.log.debug('🔍 Role mappings:', formattedMappings);
      strapi.log.info('✅ Successfully retrieved role mappings');

      return ctx.send(formattedMappings);
    } catch (error) {
      strapi.log.error('❌ Failed to retrieve role mappings:', error.response?.data || error.message);
      return ctx.badRequest('Failed to retrieve role mappings');
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
      strapi.log.warn('⚠️ Role mappings are now config-based and cannot be saved via API');
      strapi.log.info('ℹ️ Please update role mappings in config/plugins.js');

      return ctx.send({ 
        message: 'Role mappings are config-based. Please update config/plugins.js to modify role mappings.',
        success: false,
        configBased: true,
      });
    } catch (error) {
      strapi.log.error('❌ Failed to save role mappings:', error.response?.data || error.message);
      return ctx.badRequest('Failed to save role mappings');
    }
  },
};