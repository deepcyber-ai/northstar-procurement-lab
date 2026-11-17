import { computed, Injectable, signal } from '@angular/core';
import { User, UserManager, WebStorageStateStore } from 'oidc-client-ts';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { LoginResponse, TrainingUser } from './models';

@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly state = signal<LoginResponse | null>(null);
  private readonly manager = this.createManager();
  private refreshing?: Promise<User | null>;
  private readonly keys = createRemoteJWKSet(new URL('/auth/jwks', location.origin));
  private async validateIdentity(user: User): Promise<void> {
    if (!user.id_token) throw new Error('Missing ID token');
    const { payload } = await jwtVerify(user.id_token, this.keys, {
      issuer: location.origin, audience: 'northstar-spa', algorithms: ['RS256'],
      requiredClaims: ['exp', 'iat', 'sub'], clockTolerance: 30
    });
    if (payload.sub !== user.profile.sub) throw new Error('Identity mismatch');
  }
  readonly session = this.state.asReadonly();
  readonly user = computed(() => this.state()?.user ?? null);
  readonly isLoggedIn = computed(() => this.state() !== null);
  readonly isAdmin = computed(() => this.state()?.user.role.toUpperCase() === 'ADMIN');
  readonly ready = this.restore();

  private async createManager(): Promise<UserManager> {
    localStorage.removeItem('deep-cyber-sample-session');
    const response = await fetch('/auth/config', { cache: 'no-store' });
    if (!response.ok) throw new Error('Identity service unavailable');
    const config = await response.json();
    if (config.issuer !== location.origin || config.redirectUri !== location.origin + '/callback')
      throw new Error('Open the app using its configured public hostname.');
    return new UserManager({
      authority: config.issuer, client_id: config.clientId, redirect_uri: config.redirectUri,
      response_type: 'code', scope: 'openid profile offline_access northstar.api',
      userStore: new WebStorageStateStore({ store: sessionStorage }),
      stateStore: new WebStorageStateStore({ store: sessionStorage }),
      automaticSilentRenew: false, monitorSession: false, loadUserInfo: false,
      // Refresh explicitly below: never fall back to an iframe or silently repeat writes.
      staleStateAgeInSeconds: 300
    });
  }
  private async restore(): Promise<void> {
    try {
      const manager = await this.manager;
      await manager.clearStaleState();
      if (location.pathname === '/callback') return;
      const user = await manager.getUser();
      if (user) await this.loadProfile(await this.currentUser());
    } catch { this.state.set(null); }
  }
  private async currentUser(): Promise<User | null> {
    const manager = await this.manager;
    let user = await manager.getUser();
    if (user && (user.expires_in ?? 0) < 60) {
      if (!user.refresh_token) { await this.clear(); return null; }
      this.refreshing ??= manager.signinSilent().finally(() => { this.refreshing = undefined; });
      try { user = await this.refreshing; if (user) await this.validateIdentity(user); }
      catch { await this.clear(); throw new Error('Session expired. Please sign in again.'); }
    }
    return user;
  }
  private async loadProfile(user: User | null): Promise<void> {
    if (!user) { this.state.set(null); return; }
    await this.validateIdentity(user);
    const result = await fetch('/api/auth/me', { cache: 'no-store', headers: { Authorization: 'Bearer ' + user.access_token } });
    if (!result.ok) { await this.clear(); throw new Error('Session expired. Please sign in again.'); }
    const profile: TrainingUser = await result.json();
    this.state.set({ token: user.access_token, user: profile, trainingOnly: true });
  }
  async login(): Promise<void> {
    await this.ready;
    await (await this.manager).signinRedirect({ nonce: crypto.randomUUID() });
  }
  async callback(): Promise<void> {
    try {
      const user = await (await this.manager).signinRedirectCallback();
      await this.loadProfile(user);
    } catch {
      await this.clear();
      throw new Error('Sign-in could not be verified. Start sign-in again.');
    } finally {
      // Do not leave authorization codes in history, copied URLs, or referrers.
      history.replaceState({}, '', '/callback');
    }
  }
  async accessToken(): Promise<string | null> {
    await this.ready;
    const user = await this.currentUser();
    const existing = this.state();
    if (user && existing) this.state.set({ ...existing, token: user.access_token });
    return user?.access_token ?? null;
  }
  async clear(): Promise<void> {
    this.state.set(null);
    await (await this.manager).removeUser();
  }
  async logout(): Promise<void> {
    const token = await this.accessToken();
    if (token) {
      const response = await fetch('/auth/session/logout', {
        method: 'POST', credentials: 'same-origin', headers: { Authorization: 'Bearer ' + token }
      });
      if (!response.ok && response.status !== 401) throw new Error('Server sign-out failed. Please retry.');
    }
    await this.clear();
    // Also clear the IdP cookie even if the access token has already expired/revoked.
    location.assign('/auth/signed-out');
  }
}
