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

    try {
      // Construct token URL - support both full URLs and path-based config
      let tokenUrl;
      if (config.KEYCLOAK_TOKEN_URL) {
        tokenUrl = config.KEYCLOAK_TOKEN_URL.startsWith('http') 
          ? config.KEYCLOAK_TOKEN_URL
          : `${config.KEYCLOAK_AUTH_URL}${config.KEYCLOAK_TOKEN_URL}`;
      } else {
        tokenUrl = `${config.KEYCLOAK_AUTH_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/token`;
      }

      strapi.log.debug('🔍 Fetching admin token from:', tokenUrl);

      // 🔥 Send request to Keycloak for an admin token
      const tokenResponse = await axios.post(
        tokenUrl,
        new URLSearchParams({
          client_id: config.KEYCLOAK_CLIENT_ID,
          client_secret: config.KEYCLOAK_CLIENT_SECRET,
          grant_type: 'client_credentials',
          scope: config.KEYCLOAK_SCOPE || 'openid email profile',
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
      strapi.log.error('❌ Keycloak Admin Token Fetch Error:', {
        status: error.response?.status || 'Unknown',
        statusText: error.response?.statusText,
        url: error.config?.url,
        message: error.response?.data || error.message,
        hasClientSecret: !!config.KEYCLOAK_CLIENT_SECRET,
        clientId: config.KEYCLOAK_CLIENT_ID,
      });

      throw new Error('Failed to fetch Keycloak admin token');
    }
  },
});

export default keycloakService;