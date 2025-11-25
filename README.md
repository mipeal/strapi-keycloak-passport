# 🔑 Strapi Keycloak Passport Plugin
🚀 **Seamlessly integrate Keycloak authentication with Strapi Admin Panel.**  
💼 **Enterprise-grade security, role-based access control (RBAC), and streamlined authentication.**  

## ✨ Features
✅ **🔐 Single Sign-On (SSO)** – Replace Strapi's default admin login with Keycloak authentication.  
✅ **🛡️ Role Mapping** – Dynamically map Keycloak roles to Strapi admin roles.  
✅ **⚡ Auto-Assign Default Role** – Ensure a default role (`STRAPI_ADMIN → Super Admin`) exists at first-time activation.  
✅ **🔍 Strapi RBAC Integration** – Leverage Strapi's native **Roles & Permissions** to enforce admin access.  
✅ **💾 Persistent Admin Session** – No redundant authentication; login once, persist across requests.  
✅ **📜 Full Logging & Debugging** – Logs every authentication & authorization event.  
✅ **🔄 Keycloak 18+ Support** – OAuth2 Authorization Code flow for modern Keycloak versions.  
✅ **🚪 Logout URL Support** – Properly terminate Keycloak sessions on logout.  

---

## 📦 Installation
```bash
yarn add strapi-keycloak-passport
```
or
```bash
npm install strapi-keycloak-passport
```

---

## ⚙️ Configuration
### 🔹 `config/plugins.js`
Add the following entry inside your `config/plugins.js` file:

#### For Keycloak 18+ (OAuth2 Authorization Code Flow - Recommended)
```javascript
module.exports = ({ env }) => ({
  'strapi-keycloak-passport': {
    enabled: env('KEYCLOAK_PASSPORT_ACTIVE', true),
    config: {
      KEYCLOAK_AUTH_URL: env('KEYCLOAK_PASSPORT_AUTH_URL', 'https://keycloak.example.com'),
      KEYCLOAK_REALM: env('KEYCLOAK_PASSPORT_REALM', 'master'),
      KEYCLOAK_CLIENT_ID: env('KEYCLOAK_PASSPORT_CLIENT_ID', 'strapi-admin'),
      KEYCLOAK_CLIENT_SECRET: env('KEYCLOAK_PASSPORT_CLIENT_SECRET', 'your-secret'),
      // OAuth2 Authorization Code Flow (Keycloak 18+)
      KEYCLOAK_REDIRECT_URI: env('KEYCLOAK_PASSPORT_REDIRECT_URI', 'https://your-strapi-instance.com/strapi-keycloak-passport/callback'),
      KEYCLOAK_LOGOUT_REDIRECT_URI: env('KEYCLOAK_PASSPORT_LOGOUT_REDIRECT_URI', 'https://your-strapi-instance.com/admin/auth/login'),
      // Legacy password grant (for Keycloak < 18)
      KEYCLOAK_TOKEN_URL: env('KEYCLOAK_PASSPORT_TOKEN_URL', '/realms/master/protocol/openid-connect/token'),
      KEYCLOAK_USERINFO_URL: env('KEYCLOAK_PASSPORT_USERINFO_URL', '/realms/master/protocol/openid-connect/userinfo'),
      roleConfigs: {
        defaultRoleId: env('KEYCLOAK_PASSPORT_DEFAULT_ROLE_ID', 5),
        excludedRoles: env('KEYCLOAK_PASSPORT_EXZIL_ROLES', [
          'uma_authorization',
          'default-roles-centralisedcms',
          'offline_access',
          'VIEWER',
        ]),
      },
    },
  },
});
```

#### For Legacy Keycloak (< 18, Password Grant)
```javascript
module.exports = ({ env }) => ({
  'strapi-keycloak-passport': {
    enabled: env('KEYCLOAK_PASSPORT_ACTIVE', true),
    config: {
      KEYCLOAK_AUTH_URL: env('KEYCLOAK_PASSPORT_AUTH_URL', 'https://keycloak.example.com/auth'),
      KEYCLOAK_REALM: env('KEYCLOAK_PASSPORT_REALM', 'master'),
      KEYCLOAK_CLIENT_ID: env('KEYCLOAK_PASSPORT_CLIENT_ID', 'strapi-admin'),
      KEYCLOAK_CLIENT_SECRET: env('KEYCLOAK_PASSPORT_CLIENT_SECRET', 'your-secret'),
      KEYCLOAK_TOKEN_URL: env('KEYCLOAK_PASSPORT_TOKEN_URL', '/token'),
      KEYCLOAK_USERINFO_URL: env('KEYCLOAK_PASSPORT_USERINFO_URL', '/userinfo'),
      roleConfigs: {
        defaultRoleId: env('KEYCLOAK_PASSPORT_DEFAULT_ROLE_ID', 5),
        excludedRoles: env('KEYCLOAK_PASSPORT_EXZIL_ROLES', [
          'uma_authorization',
          'default-roles-centralisedcms',
          'offline_access',
          'VIEWER',
        ]),
      },
    },
  },
});
```

### 📋 Configuration Options

| Option | Description | Required |
|--------|-------------|----------|
| `KEYCLOAK_AUTH_URL` | Base URL of your Keycloak server | ✅ Yes |
| `KEYCLOAK_REALM` | Keycloak realm name | ✅ Yes |
| `KEYCLOAK_CLIENT_ID` | Client ID configured in Keycloak | ✅ Yes |
| `KEYCLOAK_CLIENT_SECRET` | Client secret from Keycloak | ✅ Yes |
| `KEYCLOAK_REDIRECT_URI` | OAuth2 callback URL (Keycloak 18+) | For OAuth2 flow |
| `KEYCLOAK_LOGOUT_REDIRECT_URI` | URL to redirect after Keycloak logout | Optional |
| `KEYCLOAK_TOKEN_URL` | Token endpoint path (legacy) | For password grant |
| `KEYCLOAK_USERINFO_URL` | UserInfo endpoint path (legacy) | For password grant |

---

## 🛠 Setup in Keycloak
### 1️⃣ Create a Client
- **Go to Keycloak Admin Panel** → `Clients`
- **Create New Client**:  
  - `Client ID`: `strapi-admin`
  - `Access Type`: **Confidential**
  - `Root URL`: `https://your-strapi-instance.com/admin`
  - **Valid Redirect URIs**: `https://your-strapi-instance.com/strapi-keycloak-passport/callback`
  - **Valid Post Logout Redirect URIs**: `https://your-strapi-instance.com/admin/auth/login`
- **Save the client**, then go to the **Credentials** tab and copy:
  - `Client Secret`
  - `Client ID`

### 2️⃣ Configure for Keycloak 18+
For Keycloak 18+, ensure the following settings:
- **Client authentication**: ON
- **Authorization**: OFF (unless needed)
- **Authentication flow**: Enable "Standard flow" (Authorization Code)
- **Direct access grants**: Can be disabled (password grant not needed)
  
### 3️⃣ Configure Admin Roles
- **Go to** `Roles` → `Create Role`
  - Role: `STRAPI_ADMIN` (This will map to **Strapi Super Admin** by default)
- Assign this role to **Keycloak users who should have Strapi Super Admin access**.

---

## 🔐 Role-Based Access Control (RBAC)
Strapi Keycloak Passport Plugin **respects Strapi's native RBAC system**.  
It maps **Keycloak roles to Strapi admin roles**.

### 🛠 Managing Role Mappings
1️⃣ **Go to**: `Admin Panel → Keycloak Plugin`  
2️⃣ **Map Keycloak roles** to Strapi admin roles.  
3️⃣ **Save the mapping.**  

🔄 **Example Mapping:**

| Keycloak Role       | Strapi Role       |
|---------------------|------------------|
| `STRAPI_ADMIN`      | `Super Admin (1)` |
| `EDITOR`           | `Editor (2)`      |
| `VIEWER`           | `Viewer (3)`      |

### 📌 How Role Mapping Works
✅ If a Keycloak user logs in with `STRAPI_ADMIN`, they get **Super Admin** rights in Strapi.  
✅ If no role mapping exists, they get **assigned the default role** (`KEYCLOAK_PASSPORT_DEFAULT_ROLE_ID`).  

---

## 🔄 Authentication Flows

### OAuth2 Authorization Code Flow (Keycloak 18+)

```mermaid
sequenceDiagram
  participant User
  participant Strapi
  participant Keycloak
  User->>Strapi: Click "Login with Keycloak"
  Strapi->>User: Redirect to Keycloak Authorization URL
  User->>Keycloak: Enter credentials
  Keycloak->>Strapi: Redirect with authorization code
  Strapi->>Keycloak: Exchange code for tokens
  Keycloak->>Strapi: Return Access Token
  Strapi->>Keycloak: Fetch User Info
  Strapi->>Strapi: Find/Create Admin User
  Strapi->>User: Redirect to Admin with JWT Token
```

### Legacy Password Grant Flow (Keycloak < 18)

```mermaid
sequenceDiagram
  participant User
  participant Strapi
  participant Keycloak
  User->>Strapi: Request login (email + password)
  Strapi->>Keycloak: Authenticate via password grant
  Keycloak->>Strapi: Return Access Token
  Strapi->>Keycloak: Fetch User Info
  Strapi->>Strapi: Find/Create Admin User
  Strapi->>User: Return JWT Token
```

✅ **Admin logs in once** → session persists, no re-authentication needed on every request.  

---

## 📜 API Endpoints
| Method | Endpoint | Description | Auth Required |
|--------|---------|-------------|--------------|
| `POST` | `/admin/login` | Authenticate admin via Keycloak (password grant) | ❌ No |
| `GET` | `/authorize` | Initiate OAuth2 Authorization Code flow | ❌ No |
| `GET` | `/callback` | OAuth2 callback endpoint | ❌ No |
| `GET` | `/authorization-url` | Get Keycloak authorization URL | ❌ No |
| `GET` | `/logout-url` | Get Keycloak logout URL | ❌ No |
| `GET` | `/keycloak-roles` | Fetch available Keycloak roles | ✅ Yes |
| `GET` | `/get-keycloak-role-mappings` | Get saved role mappings | ✅ Yes |
| `POST` | `/save-keycloak-role-mappings` | Save new role mappings | ✅ Yes |

---

## 🚪 Logout Support

To properly logout from both Strapi and Keycloak:

1. **Get the logout URL** by calling `/strapi-keycloak-passport/logout-url`
2. **Clear Strapi session/JWT** on the client side
3. **Redirect to the Keycloak logout URL** to terminate the Keycloak session

Example:
```javascript
// Fetch logout URL
const response = await fetch('/strapi-keycloak-passport/logout-url');
const { logoutUrl } = await response.json();

// Clear local storage/session
localStorage.removeItem('jwtToken');

// Redirect to Keycloak logout
window.location.href = logoutUrl;
```

---

## 🚀 Next-Level Security
| Feature | Status |
|---------|--------|
| ✅ OAuth2 Authorization Code Flow | ✔ Keycloak 18+ |
| ✅ Legacy Password Grant | ✔ Keycloak < 18 |
| ✅ Keycloak Logout Integration | ✔ Session Termination |
| ✅ Session-Based Persistence | ✔ Secure |
| ✅ Role-Based Access Control (RBAC) | ✔ Strapi Admin Integration |
| ✅ Middleware Protection | ✔ Only Authorized Users Access APIs |
| ✅ CSRF Protection | ✔ State Parameter Validation |

---

## 🎯 Final Command to Rule Them All
```bash
yarn develop
```
🔥 **Your Strapi is now fully Keycloak-powered!** 🔥  
