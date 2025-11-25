import axios from 'axios';

/**
 * @module KeycloakService
 * @description Handles Keycloak authentication and provides utility functions.
 * @param {Object} strapi - Strapi instance.
 * @returns {Object} - Keycloak service methods.
 */
const keycloakService = ({ strapi }) => ({
  /**
   * Fetches an admin access token from Keycloak.
   *
   * @async
   * @function fetchAdminToken
   * @returns {Promise<string>} The Keycloak access token.
   * @throws {Error} If authentication fails.
   */
  async fetchAdminToken() {
    const config = strapi.config.get('plugin::strapi-keycloak-passport');
    const isDebugMode = config?.debug === true;

    try {
      const tokenEndpoint = `${config.KEYCLOAK_AUTH_URL}/auth/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`;

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Fetching admin token from Keycloak:', {
          tokenEndpoint,
          clientId: config.KEYCLOAK_CLIENT_ID,
          grantType: 'client_credentials',
        });
      }

      // 🔥 Send request to Keycloak for an admin token
      const tokenResponse = await axios.post(
        tokenEndpoint,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          grant_type: 'client_credentials',
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      /** @type {string | undefined} */
      const accessToken = tokenResponse.data?.access_token;

      // 🔄 Ensure access token is valid
      if (!accessToken) {
        throw new Error('❌ Keycloak returned an empty access token');
      }

      strapi.log.info('✅ Successfully fetched Keycloak admin token.');
      return accessToken;
    } catch (error) {
      const errorDetails = {
        status: error.response?.status || 'Unknown',
        message: error.response?.data?.error_description || error.response?.data?.error || error.message,
        responseData: error.response?.data || null,
      };

      strapi.log.error('❌ Keycloak Admin Token Fetch Error:', isDebugMode ? errorDetails : {
        status: errorDetails.status,
        message: errorDetails.message,
      });

      if (isDebugMode) {
        strapi.log.debug('🔍 Debug - Admin token fetch error details:', {
          errorMessage: error.message,
          errorStack: error.stack,
          responseStatus: error.response?.status,
          responseData: error.response?.data,
          requestUrl: error.config?.url,
          tokenEndpoint: `${config.KEYCLOAK_AUTH_URL}/auth/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`,
          clientId: config.KEYCLOAK_CLIENT_ID,
        });
      }

      const detailedMessage = isDebugMode
        ? `Failed to fetch Keycloak admin token: ${errorDetails.message}`
        : 'Failed to fetch Keycloak admin token';

      throw new Error(detailedMessage);
    }
  },
});

export default keycloakService;