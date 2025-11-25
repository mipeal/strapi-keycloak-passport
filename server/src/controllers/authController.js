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
      const isDebugMode = config?.debug === true;

      // 🔑 Get Admin Token
      const accessToken = await strapi
        .plugin('strapi-keycloak-passport')
        .service('keycloakService')
        .fetchAdminToken();

      const rolesEndpoint = `${config.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config.KEYCLOAK_REALM}/roles`;

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Fetching Keycloak roles from:', {
          rolesEndpoint,
          excludedRoles: config.roleConfigs.excludedRoles,
        });
      }

      // 🔍 Fetch Keycloak Roles using Admin Token
      const rolesResponse = await axios.get(
        rolesEndpoint,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      /** @type {Object[]} */
      const keycloakRoles = rolesResponse.data.filter(
        role => !config.roleConfigs.excludedRoles.includes(role.name)
      );

      /** @type {Object[]} */
      const strapiRoles = await strapi.entityService.findMany('admin::role', {});

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Fetched roles:', {
          keycloakRolesCount: keycloakRoles.length,
          strapiRolesCount: strapiRoles.length,
          keycloakRoleNames: keycloakRoles.map(r => r.name),
          strapiRoleNames: strapiRoles.map(r => r.name),
        });
      }

      return ctx.send({ keycloakRoles, strapiRoles });
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error(
        '❌ Failed to fetch Keycloak roles: Have you tried giving the role "MANAGE-REALM" and "MANAGE-USERS"?',
        error.response?.data || error.message
      );

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Keycloak roles fetch error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          responseStatus: error.response?.status,
          responseData: error.response?.data,
          rolesEndpoint: `${config?.KEYCLOAK_AUTH_URL}/auth/admin/realms/${config?.KEYCLOAK_REALM}/roles`,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to fetch Keycloak roles: ${error.response?.data?.error_description || error.message}` : 'Failed to fetch Keycloak roles');
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
      const mappings = await strapi
        .service('plugin::strapi-keycloak-passport.roleMappingService')
        .getMappings();

      // Convert array of mappings into an object
      /** @type {Object} */
      const formattedMappings = mappings.reduce((acc, mapping) => {
        acc[mapping.keycloakRole] = mapping.strapiRole;
        return acc;
      }, {});

      return ctx.send(formattedMappings);
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('❌ Failed to retrieve role mappings:', error.response?.data || error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Role mappings retrieval error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to retrieve role mappings: ${error.message}` : 'Failed to retrieve role mappings');
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
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      /** @type {Object<string, number>} */
      const { mappings } = ctx.request.body;

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Saving role mappings:', {
          mappings,
        });
      }

      await strapi.plugin('strapi-keycloak-passport')
        .service('roleMappingService')
        .saveMappings(mappings);

      return ctx.send({ message: 'Mappings saved successfully.' });
    } catch (error) {
      const config = strapi.config.get('plugin::strapi-keycloak-passport');
      const isDebugMode = config?.debug === true;

      strapi.log.error('❌ Failed to save role mappings:', error.response?.data || error.message);

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Role mappings save error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          requestBody: ctx.request.body,
        });
      }

      return ctx.badRequest(isDebugMode ? `Failed to save role mappings: ${error.message}` : 'Failed to save role mappings');
    }
  },
};