/*
 * HomePage Component
 *
 * @module HomePage
 * @description UI for mapping Keycloak roles to Strapi roles in Strapi Admin panel.
 */

import React, { useReducer, useEffect } from 'react';
import axios from 'axios';
import {
  Box,
  Typography,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Loader,
  Alert,
} from '@strapi/design-system';
import { Collapse } from '@strapi/icons';

/**
 * @typedef {Object} HomePageState
 * @property {Object[]} keycloakRoles - Array of Keycloak roles.
 * @property {Object[]} strapiRoles - Array of Strapi roles.
 * @property {Object<string, number>} roleMappings - Mapping of Keycloak roles to Strapi role IDs.
 * @property {boolean} loading - Indicates if data is being fetched.
 * @property {string|null} error - Error message (if any).
 * @property {boolean} success - Indicates if mappings were saved successfully.
 */

/**
 * Initial state for the HomePage reducer.
 * @type {HomePageState}
 */
const initialState = {
  keycloakRoles: [],
  strapiRoles: [],
  roleMappings: {},
  loading: true,
  error: null,
  success: false,
};

/**
 * Reducer function to manage HomePage state.
 *
 * @param {HomePageState} state - Current state.
 * @param {Object} action - Dispatched action.
 * @returns {HomePageState} - Updated state.
 */
const reducer = (state, action) => {
  switch (action.type) {
    case 'SET_DATA':
      return { ...state, ...action.payload, loading: false };
    case 'SET_ERROR':
      return { ...state, error: action.error, loading: false };
    default:
      return state;
  }
};

/**
 * HomePage Component
 *
 * @returns {JSX.Element} Component for managing role mappings between Keycloak and Strapi.
 */
const HomePage = () => {
  /** @type {HomePageState, React.Dispatch<{ type: string, payload?: any }>}} */
  const [state, dispatch] = useReducer(reducer, initialState);

  useEffect(() => {
    /**
     * Fetches roles from Keycloak and Strapi, and retrieves saved mappings.
     *
     * @async
     * @function fetchRoles
     */
    async function fetchRoles() {
      try {
        const [rolesResponse, mappingsResponse] = await Promise.all([
          axios.get('/strapi-keycloak-passport/keycloak-roles'),
          axios.get('/strapi-keycloak-passport/get-keycloak-role-mappings'),
        ]);

        dispatch({
          type: 'SET_DATA',
          payload: {
            keycloakRoles: rolesResponse.data.keycloakRoles,
            strapiRoles: rolesResponse.data.strapiRoles,
            roleMappings: mappingsResponse.data,
          },
        });
      } catch (err) {
        dispatch({ type: 'SET_ERROR', error: 'Failed to fetch roles. Please check Keycloak settings.' });
      }
    }

    fetchRoles();
  }, []);

  if (state.loading) return <Loader>Loading roles...</Loader>;

  return (
    <Box padding={10} background="neutral0" shadow="filterShadow" borderRadius="12px">
      <Typography variant="alpha" as="h1" fontWeight="bold">
        Passport Role Mapping
      </Typography>

      <Box paddingTop={2} paddingBottom={4}>
        <Typography variant="epsilon" textColor="neutral600" paddingTop={2} paddingBottom={4}>
          View Keycloak roles and their mapped Strapi admin roles. Role mappings are configured via environment variables.
        </Typography>
      </Box>

      {state.error && (
        <Box paddingBottom={4}>
          <Alert title="Error" variant="danger" startIcon={<Collapse />}>
            {state.error}
          </Alert>
        </Box>
      )}

      <Box background="transparent">
        <Table colCount={2} rowCount={state.keycloakRoles.length + 1}>
          <Thead>
            <Tr>
              <Th>Keycloak Role</Th>
              <Th>Strapi Role</Th>
            </Tr>
          </Thead>
          <Tbody>
            {state.keycloakRoles.map((kcRole) => (
              <Tr key={kcRole.id}>
                <Td>
                  <Typography textColor="neutral800">{kcRole.name}</Typography>
                </Td>
                <Td>
                  <Typography textColor="neutral600">
                    {state.roleMappings[kcRole.name] 
                      ? state.strapiRoles.find(r => r.id === state.roleMappings[kcRole.name])?.name || '-'
                      : '-'}
                  </Typography>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </Box>
    </Box>
  );
};

export { HomePage };