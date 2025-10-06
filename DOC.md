# Angular Keycloak Scaffolder Template

This is a generic, reusable Angular Standalone Component template designed to be used as a base for micro-frontends in platforms like Spotify Backstage. It comes pre-configured with **Keycloak** authentication logic using Angular Signals and an **HTTP Interceptor** to automatically attach the JWT token to outgoing API requests.

## 1. Prerequisites

Before running the application, ensure you have:

1. **Node.js & npm:** Installed on your system.

2. **Angular CLI:** Installed globally (`npm install -g @angular/cli`).

3. **Keycloak Instance:** A running Keycloak server (local or remote) with a configured Realm and Client.

## 2. Installation and Setup

### A. Clone and Install Dependencies

1. Clone this repository or generate the project using your scaffolder tool.

2. Install the required `keycloak-js` library:

   ```
   npm install keycloak-js
   npm install 
   
   ```

### B. Configure Keycloak Settings

The primary configuration happens within the **`KeycloakAuthService`** (which is currently defined inside `src/app/app.component.ts`).

You must update the configuration object to point to your specific Keycloak setup.

Locate the following section in `src/app/app.component.ts` (or the file containing the `App` component) and modify the `keycloakConfig` properties:

```
// Inside KeycloakAuthService class in app.component.ts

// Configurazione Keycloak
private readonly keycloakConfig = {
    // ⚠️ UPDATE THIS: The URL of your Keycloak server and base path
    url: 'http://localhost:8080/auth', 
    
    // ⚠️ UPDATE THIS: The Realm name configured in Keycloak
    realm: 'il_tuo_realm', 
    
    // ⚠️ UPDATE THIS: The Client ID of this application registered in Keycloak
    clientId: 'il_tuo_client_id' 
};

```

### C. Update Main Bootstrap File (If necessary)

Ensure your main bootstrap file (`src/main.ts`) correctly imports and runs the `App` component:

```
// src/main.ts
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { App, KeycloakAuthService } from './app/app.component'; // Ensure correct path

bootstrapApplication(App, {
  providers: [
    // This enables the HTTP Client and Interceptor functionality
    provideHttpClient(withInterceptors([])), 
    KeycloakAuthService 
  ]
}).catch(err => console.error(err));

```

## 3. How Authentication Works

### A. Keycloak Initialization (The Core)

The `KeycloakAuthService` is initialized when the application starts (`ngOnInit`). It performs the following steps:

1. Calls `keycloak.init()` with options like `onLoad: 'check-sso'` to silently check for an existing valid session.

2. Updates the **`isLoggedIn`** and **`isReady`** Signals based on the initialization result.

3. If authenticated, it calls `keycloak.loadUserProfile()` and sets the **`userProfile`** Signal.

### B. Automatic Token Attachment (The Interceptor)

The most important feature for API communication is the **`keycloakTokenInterceptor`**.

This interceptor is registered globally and executes for every outgoing HTTP request made via `HttpClient`.

1. It checks the `KeycloakAuthService` for the current JWT token (`kc.token`).

2. It creates a clone of the request, adding the `Authorization` header in the format: `Authorization: Bearer <JWT_TOKEN>`.

3. This ensures that all protected backend endpoints automatically receive the necessary credential without boilerplate code in every component.

### C. Using the Protected API

The `App` component demonstrates how to call a protected resource using the injected `HttpClient`:

```
// In App component
callProtectedApi() {
    // The interceptor handles adding the token automatically
    this.http.get('/api/protected/resource', { /* ... */ }).subscribe({
        // ... handle response
    });
}

```

## 4. Running the Application

After configuration, you can start the development server:

```
ng serve

```

Open your browser to `http://localhost:4200` and test the **Login with Keycloak** button and the **Call Protected API** button.
        
