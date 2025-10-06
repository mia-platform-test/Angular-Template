import { ChangeDetectionStrategy, Component, signal, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpInterceptorFn, provideHttpClient, withInterceptors } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';
import { catchError, map, of, tap } from 'rxjs';

// --- INIZIO DEFINIZIONE SIMULATA KEYCLOAK ---
// In un progetto reale, importeresti 'Keycloak' da 'keycloak-js'.
// Qui simuliamo l'interfaccia Keycloak per dimostrare la logica Angular.

interface KeycloakInstance {
  init(options: any): Promise<boolean>;
  login(options?: any): Promise<void>;
  logout(options?: any): Promise<void>;
  isTokenExpired(minValidity?: number): boolean;
  token?: string;
  loadUserProfile(): Promise<KeycloakProfile>;
}

interface KeycloakProfile {
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  name?: string;
  preferred_username?: string;
  // Aggiungi altre proprietà Keycloak che ti servono
}

// Simulazione dell'oggetto Keycloak globale (che avresti dopo l'import)
// Qui definiamo la logica simulata di autenticazione per il template.
const mockKeycloak: KeycloakInstance = {
  // Simula l'inizializzazione: se è la prima volta, imposta loggedIn a false.
  // In un ambiente reale, Keycloak.init() gestisce il check del token.
  init: async (options: any) => {
    // Simuliamo un ritardo di inizializzazione
    await new Promise(resolve => setTimeout(resolve, 1000)); 
    const isAuthenticated = localStorage.getItem('kc_auth') === 'true';
    if (isAuthenticated) {
        // Se simuliamo che un utente è già loggato (da sessione precedente)
        mockKeycloak.token = 'mock-jwt-token-12345';
        return true;
    }
    return false;
  },
  login: async (options?: any) => {
    await new Promise(resolve => setTimeout(resolve, 500));
    localStorage.setItem('kc_auth', 'true');
    mockKeycloak.token = 'mock-jwt-token-' + Math.random().toString(36).substring(2, 9);
    window.location.reload(); // In Keycloak, un login di successo spesso causa un redirect/refresh
  },
  logout: async (options?: any) => {
    await new Promise(resolve => setTimeout(resolve, 500));
    localStorage.removeItem('kc_auth');
    mockKeycloak.token = undefined;
    window.location.reload(); 
  },
  isTokenExpired: (minValidity?: number) => {
    // In un'app reale, questo controllerebbe la data di scadenza del token
    return false;
  },
  loadUserProfile: async () => {
    await new Promise(resolve => setTimeout(resolve, 300));
    return {
      username: 'utente.template',
      email: 'utente.template@scaffolder.it',
      name: 'Utente Template'
    } as KeycloakProfile;
  },
  token: undefined, // Il token JWT
};

// --- FINE DEFINIZIONE SIMULATA KEYCLOAK ---


// ************************************************
// 3. LOGICA DELL'INTERCEPTOR HTTP (CRUCIALE)
// ************************************************
// Questo Interceptor HTTP aggiunge l'header 'Authorization' con il token Keycloak 
// a ogni richiesta in uscita, tranne che per il server Keycloak stesso.

const keycloakTokenInterceptor: HttpInterceptorFn = (req, next) => {
  const keycloakService = inject(KeycloakAuthService);
  const token = keycloakService.keycloakInstance()?.token;

  if (token && !req.url.includes('keycloak-server-url')) {
    const authReq = req.clone({
      headers: req.headers.set('Authorization', `Bearer ${token}`)
    });
    console.log(`[Interceptor] Token allegato per: ${req.url}`);
    return next(authReq);
  }

  console.log(`[Interceptor] Nessun token allegato per: ${req.url}`);
  return next(req);
};


// ************************************************
// 2. SERVIZIO KEYCLOAK AUTONOMO (KeycloakAuthService)
// ************************************************
// Questo servizio gestisce lo stato di autenticazione utilizzando i Signals.

@Component({
  standalone: true,
  selector: 'keycloak-auth-service',
  template: '', // Non ha un template, è solo un provider di logica
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class KeycloakAuthService implements OnInit {
  // Configurazione Keycloak
  private readonly keycloakConfig = {
    url: 'http://localhost:8080/auth', // Sostituisci con il tuo URL
    realm: 'il_tuo_realm',
    clientId: 'il_tuo_client_id'
  };

  // Stato gestito tramite Signals
  keycloakInstance = signal<KeycloakInstance | undefined>(undefined);
  isLoggedIn = signal(false);
  isReady = signal(false);
  userProfile = signal<KeycloakProfile | undefined>(undefined);
  
  // Ottieni un'istanza simulata di Keycloak o la Keycloak reale se la importi.
  private kc: KeycloakInstance = mockKeycloak; 

  constructor() {
    this.keycloakInstance.set(this.kc);
  }

  ngOnInit(): void {
    this.initKeycloak();
  }

  private async initKeycloak() {
    try {
      console.log('Inizializzazione Keycloak in corso...');
      const authenticated = await this.kc.init({
        onLoad: 'check-sso', // Usa 'login-required' se vuoi forzare il login all'avvio
        silentCheckSsoRedirectUri: window.location.origin + '/assets/silent-check-sso.html',
        pkceMethod: 'S256',
        // In un'app reale, useresti i valori di config qui sopra:
        // url: this.keycloakConfig.url, ...
      });
      
      this.isLoggedIn.set(authenticated);
      this.isReady.set(true);

      if (authenticated) {
        await this.loadUserProfile();
        console.log('Autenticazione riuscita. Token valido.');
      } else {
        console.log('Non autenticato.');
      }
    } catch (error) {
      console.error('Errore durante l\'inizializzazione di Keycloak:', error);
      this.isReady.set(true);
      this.isLoggedIn.set(false);
    }
  }

  private async loadUserProfile(): Promise<void> {
    try {
      const profile = await this.kc.loadUserProfile();
      this.userProfile.set(profile);
    } catch (error) {
      console.error('Errore durante il caricamento del profilo utente:', error);
    }
  }

  public login(): void {
    if (this.kc) {
      this.kc.login();
    }
  }

  public logout(): void {
    if (this.kc) {
      this.kc.logout();
    }
  }
}


// ************************************************
// 1. COMPONENTE PRINCIPALE DELL'APPLICAZIONE (APP)
// ************************************************

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule],
  // Nota: I providers per HttpClient e l'Interceptor andrebbero in app.config.ts (non nel componente)
  // Qui li aggiungiamo al componente per l'esempio standalone
  providers: [
    KeycloakAuthService,
    provideHttpClient(withInterceptors([keycloakTokenInterceptor])) // Aggiunge HttpClient e l'Interceptor
  ],
  template: `
    <!-- Header e Status Bar -->
    <header class="bg-gray-900 shadow-md p-4 text-white">
      <div class="max-w-7xl mx-auto flex justify-between items-center">
        <h1 class="text-2xl font-extrabold tracking-tight text-indigo-400">
          <span class="mr-2">🚀</span> Scaffolder Keycloak
        </h1>
        <div class="flex items-center space-x-4">
          @if (!kcService.isReady()) {
            <span class="text-sm text-yellow-400 flex items-center">
              <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Inizializzazione Keycloak...
            </span>
          } @else if (kcService.isLoggedIn()) {
            <span class="text-sm font-medium text-green-400">
              Bentornato, {{ kcService.userProfile()?.preferred_username || kcService.userProfile()?.name || 'Utente' }}
            </span>
            <button (click)="kcService.logout()"
              class="px-4 py-2 bg-red-600 text-white text-sm font-semibold rounded-lg shadow-md hover:bg-red-700 transition duration-150">
              Logout
            </button>
          } @else {
            <span class="text-sm font-medium text-red-400">
              Non Autenticato
            </span>
            <button (click)="kcService.login()"
              class="px-4 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg shadow-md hover:bg-indigo-700 transition duration-150"
              [disabled]="!kcService.isReady()">
              Login con Keycloak
            </button>
          }
        </div>
      </div>
    </header>

    <!-- Contenuto Principale -->
    <main class="p-8 max-w-7xl mx-auto">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
        
        <!-- Stato di Autenticazione -->
        <div class="bg-white p-6 rounded-xl shadow-2xl md:col-span-1">
          <h2 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">Stato Globale</h2>
          <p class="mb-2">
            <span class="font-semibold text-gray-600">Pronto:</span> 
            <span [ngClass]="kcService.isReady() ? 'text-green-500' : 'text-yellow-500'">
              {{ kcService.isReady() ? 'Sì' : 'No' }}
            </span>
          </p>
          <p class="mb-4">
            <span class="font-semibold text-gray-600">Loggato:</span> 
            <span [ngClass]="kcService.isLoggedIn() ? 'text-green-500' : 'text-red-500'">
              {{ kcService.isLoggedIn() ? 'Sì' : 'No' }}
            </span>
          </p>

          @if (kcService.isLoggedIn()) {
            <div class="bg-gray-50 p-4 rounded-lg">
              <h3 class="font-bold text-md mb-2 text-indigo-600">Dati Utente (Profilo)</h3>
              <ul class="text-sm space-y-1">
                <li class="flex justify-between">
                  <span class="text-gray-500">Username:</span>
                  <span class="font-mono text-gray-700">{{ kcService.userProfile()?.username }}</span>
                </li>
                <li class="flex justify-between">
                  <span class="text-gray-500">Nome Completo:</span>
                  <span class="font-mono text-gray-700">{{ kcService.userProfile()?.name }}</span>
                </li>
                <li class="flex justify-between">
                  <span class="text-gray-500">Email:</span>
                  <span class="font-mono text-gray-700">{{ kcService.userProfile()?.email }}</span>
                </li>
              </ul>
            </div>
            <div class="mt-4">
              <h3 class="font-bold text-md mb-2 text-indigo-600">Token JWT</h3>
              <textarea readonly class="w-full h-24 p-2 text-xs font-mono bg-gray-900 text-green-400 rounded-lg overflow-auto border border-gray-700 resize-none">{{ kcService.keycloakInstance()?.token || 'Token non disponibile' }}</textarea>
            </div>
          }
        </div>

        <!-- Funzionalità API Protetta -->
        <div class="bg-white p-6 rounded-xl shadow-2xl md:col-span-2">
          <h2 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">Simulazione Chiamata API Protetta</h2>
          <p class="text-gray-600 mb-4">Questa sezione simula una chiamata ad un endpoint backend che richiede il token JWT allegato dall'Interceptor HTTP.</p>

          <button 
            (click)="callProtectedApi()"
            [disabled]="!kcService.isLoggedIn() || isCallingApi()"
            class="px-6 py-3 bg-teal-600 text-white font-bold rounded-lg shadow-md hover:bg-teal-700 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed">
            {{ isCallingApi() ? 'Chiamata in corso...' : 'Chiama API Protetta' }}
          </button>

          <div class="mt-6 p-4 bg-gray-100 rounded-lg border">
            <h3 class="font-bold text-gray-700 mb-2">Risposta API:</h3>
            @if (apiResult()) {
              <pre class="whitespace-pre-wrap text-sm font-mono text-gray-800">{{ apiResult() }}</pre>
            } @else {
              <p class="text-gray-500 text-sm italic">Nessuna chiamata effettuata o in attesa...</p>
            }
          </div>
        </div>
      </div>
    </main>
  `,
  styles: [`
    :host {
      display: block;
      min-height: 100vh;
      background-color: #f4f7f9;
      font-family: 'Inter', sans-serif;
    }
  `],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class App {
  // Inietta il servizio Keycloak
  public kcService = inject(KeycloakAuthService);
  private http = inject(HttpClient);

  // Stato per la chiamata API
  isCallingApi = signal(false);
  apiResult = signal<string | null>(null);

  /**
   * Simula la chiamata a un backend protetto.
   * L'Interceptor HTTP (keycloakTokenInterceptor) allegherà automaticamente il token.
   */
  callProtectedApi() {
    if (!this.kcService.isLoggedIn()) {
        this.apiResult.set('Accesso negato: devi essere loggato.');
        return;
    }
    
    this.isCallingApi.set(true);
    this.apiResult.set(null);

    // Endpoint API simulato (sostituisci con il tuo endpoint reale)
    const mockApiUrl = '/api/protected/resource'; 
    
    // Simula una chiamata HTTP reale che l'Interceptor intercetterebbe
    this.http.get(mockApiUrl, { observe: 'response', responseType: 'text' }).pipe(
      // Simula una risposta di successo dal backend
      tap(() => {
        // In un'app reale, useresti i dati restituiti dal server
        this.apiResult.set(JSON.stringify({ 
          status: 200, 
          message: 'Dati protetti ricevuti con successo!',
          verified_by_token: true,
          user_id: this.kcService.userProfile()?.username 
        }, null, 2));
      }),
      // Simula un errore (es. token scaduto o 401/403)
      catchError((error) => {
        this.apiResult.set(`Errore nella chiamata API (401/403 simulato): ${error.message}`);
        return of(null); // Non propagare l'errore nell'observable
      }),
    ).subscribe({
      complete: () => this.isCallingApi.set(false)
    });
  }
}

// Nota per l'esecuzione in un ambiente reale:
// Per avviare l'app, dovrai aggiungere il seguente codice nel tuo 'main.ts'
/*
import { bootstrapApplication } from '@angular/platform-browser';
import { App } from './app/app.component';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { keycloakTokenInterceptor } from './app/app.component'; // Importa l'Interceptor

bootstrapApplication(App, {
  providers: [
    provideHttpClient(withInterceptors([keycloakTokenInterceptor])),
    // Aggiungi qui gli altri provider necessari
  ]
}).catch(err => console.error(err));
*/
