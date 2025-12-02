"use strict";
Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
const jsxRuntime = require("react/jsx-runtime");
const admin = require("@strapi/strapi/admin");
const designSystem = require("@strapi/design-system");
const reactRouterDom = require("react-router-dom");
const react = require("react");
const axios = require("axios");
const icons = require("@strapi/icons");
const _interopDefault = (e) => e && e.__esModule ? e : { default: e };
const axios__default = /* @__PURE__ */ _interopDefault(axios);
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
  const [state, dispatch] = react.useReducer(reducer, initialState);
  react.useEffect(() => {
    async function fetchRoles() {
      try {
        const [rolesResponse, mappingsResponse] = await Promise.all([
          axios__default.default.get("/strapi-keycloak-passport/keycloak-roles"),
          axios__default.default.get("/strapi-keycloak-passport/get-keycloak-role-mappings")
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
  if (state.loading) return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Loader, { children: "Loading roles..." });
  return /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { padding: 10, background: "neutral0", shadow: "filterShadow", borderRadius: "12px", children: [
    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "alpha", as: "h1", fontWeight: "bold", children: "Passport Role Mapping" }),
    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingTop: 2, paddingBottom: 4, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "epsilon", textColor: "neutral600", paddingTop: 2, paddingBottom: 4, children: "View Keycloak roles and their mapped Strapi admin roles. Role mappings are configured via environment variables." }) }),
    state.error && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingBottom: 4, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Alert, { title: "Error", variant: "danger", startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Collapse, {}), children: state.error }) }),
    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { background: "transparent", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Table, { colCount: 2, rowCount: state.keycloakRoles.length + 1, children: [
      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Thead, { children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: "Keycloak Role" }),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: "Strapi Role" })
      ] }) }),
      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Tbody, { children: state.keycloakRoles.map((kcRole) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { textColor: "neutral800", children: kcRole.name }) }),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { textColor: "neutral600", children: state.roleMappings[kcRole.name] ? state.strapiRoles.find((r) => r.id === state.roleMappings[kcRole.name])?.name || "-" : "-" }) })
      ] }, kcRole.id)) })
    ] }) })
  ] });
};
const App = () => {
  return /* @__PURE__ */ jsxRuntime.jsx(designSystem.DesignSystemProvider, { children: /* @__PURE__ */ jsxRuntime.jsxs(reactRouterDom.Routes, { children: [
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { index: true, element: /* @__PURE__ */ jsxRuntime.jsx(HomePage, {}) }),
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { path: "*", element: /* @__PURE__ */ jsxRuntime.jsx(admin.Page.Error, {}) })
  ] }) });
};
exports.App = App;
