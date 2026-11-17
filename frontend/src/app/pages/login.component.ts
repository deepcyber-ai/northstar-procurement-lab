import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { SessionService } from '../core/session.service';

@Component({
  selector: 'app-login',
  template: `
    <section class="page">
      <div class="eyebrow">Northstar Procurement</div>
      <h1>Purchasing, without the paperwork.</h1>
      <p class="lead">Manage orders, submit approvals and keep purchasing activity visible across your organisation.</p>
      <h2>Welcome back</h2>
      <p>Sign in to your purchasing workspace.</p>
      <button class="primary" (click)="login()" [disabled]="busy()">{{ busy() ? 'Connecting…' : 'Sign in' }}</button>
      @if (error()) { <p class="callout error" role="alert">{{ error() }}</p> }
    </section>
  `,
  styles: '.page { max-width: 960px; margin: 8vh auto; padding: 2rem; }',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent {
  private readonly session = inject(SessionService);
  readonly busy = signal(false);
  readonly error = signal('');
  async login(): Promise<void> {
    this.busy.set(true);
    try { await this.session.login(); }
    catch { this.error.set('Unable to start sign-in. Please try again.'); this.busy.set(false); }
  }
}
