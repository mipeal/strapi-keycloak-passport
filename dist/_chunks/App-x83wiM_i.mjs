import { jsx, jsxs } from "react/jsx-runtime";
import { Page } from "@strapi/strapi/admin";
import { Loader, Box, Typography, Alert, Table, Thead, Tr, Th, Tbody, Td, DesignSystemProvider } from "@strapi/design-system";
import { Routes, Route } from "react-router-dom";
import { useReducer, useEffect } from "react";
import axios from "axios";
import { Collapse } from "@strapi/icons";
const initialState = {
  keycloakRoles: [],
  strapiRoles: [],
  roleMappings: {},
  loading: true,
  error: null,
  success: false
};
const reducer = (state, action) => {
  switch (action.type) {
    case "SET_DATA":
      return { ...state, ...action.payload, loading: false };
    case "SET_ERROR":
      return { ...state, error: action.error, loading: false };
    default:
      return state;
  }
};
const HomePage = () => {
  const [state, dispatch] = useReducer(reducer, initialState);
  useEffect(() => {
    async function fetchRoles() {
      try {
        const [rolesResponse, mappingsResponse] = await Promise.all([
          axios.get("/strapi-keycloak-passport/keycloak-roles"),
          axios.get("/strapi-keycloak-passport/get-keycloak-role-mappings")
        ]);
        dispatch({
          type: "SET_DATA",
          payload: {
            keycloakRoles: rolesResponse.data.keycloakRoles,
            strapiRoles: rolesResponse.data.strapiRoles,
            roleMappings: mappingsResponse.data
          }
        });
      } catch (err) {
        dispatch({ type: "SET_ERROR", error: "Failed to fetch roles. Please check Keycloak settings." });
      }
    }
    fetchRoles();
  }, []);
  if (state.loading) return /* @__PURE__ */ jsx(Loader, { children: "Loading roles..." });
  return /* @__PURE__ */ jsxs(Box, { padding: 10, background: "neutral0", shadow: "filterShadow", borderRadius: "12px", children: [
    /* @__PURE__ */ jsx(Typography, { variant: "alpha", as: "h1", fontWeight: "bold", children: "Passport Role Mapping" }),
    /* @__PURE__ */ jsx(Box, { paddingTop: 2, paddingBottom: 4, children: /* @__PURE__ */ jsx(Typography, { variant: "epsilon", textColor: "neutral600", paddingTop: 2, paddingBottom: 4, children: "View Keycloak roles and their mapped Strapi admin roles. Role mappings are configured via environment variables." }) }),
    state.error && /* @__PURE__ */ jsx(Box, { paddingBottom: 4, children: /* @__PURE__ */ jsx(Alert, { title: "Error", variant: "danger", startIcon: /* @__PURE__ */ jsx(Collapse, {}), children: state.error }) }),
    /* @__PURE__ */ jsx(Box, { background: "transparent", children: /* @__PURE__ */ jsxs(Table, { colCount: 2, rowCount: state.keycloakRoles.length + 1, children: [
      /* @__PURE__ */ jsx(Thead, { children: /* @__PURE__ */ jsxs(Tr, { children: [
        /* @__PURE__ */ jsx(Th, { children: "Keycloak Role" }),
        /* @__PURE__ */ jsx(Th, { children: "Strapi Role" })
      ] }) }),
      /* @__PURE__ */ jsx(Tbody, { children: state.keycloakRoles.map((kcRole) => /* @__PURE__ */ jsxs(Tr, { children: [
        /* @__PURE__ */ jsx(Td, { children: /* @__PURE__ */ jsx(Typography, { textColor: "neutral800", children: kcRole.name }) }),
        /* @__PURE__ */ jsx(Td, { children: /* @__PURE__ */ jsx(Typography, { textColor: "neutral600", children: state.roleMappings[kcRole.name] ? state.strapiRoles.find((r) => r.id === state.roleMappings[kcRole.name])?.name || "-" : "-" }) })
      ] }, kcRole.id)) })
    ] }) })
  ] });
};
const App = () => {
  return /* @__PURE__ */ jsx(DesignSystemProvider, { children: /* @__PURE__ */ jsxs(Routes, { children: [
    /* @__PURE__ */ jsx(Route, { index: true, element: /* @__PURE__ */ jsx(HomePage, {}) }),
    /* @__PURE__ */ jsx(Route, { path: "*", element: /* @__PURE__ */ jsx(Page.Error, {}) })
  ] }) });
};
export {
  App
};
