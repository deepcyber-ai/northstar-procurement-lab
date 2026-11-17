import { Component, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { SessionService } from '../core/session.service';
@Component({
  selector: 'app-callback', imports: [RouterLink],
  template: '<section class="page"><h1>Signing in</h1><p role="status">{{ message() }}</p><a routerLink="/login">Back to sign in</a></section>'
})
export class CallbackComponent {
  readonly message = signal('Verifying your session…');
  private readonly router = inject(Router);
  constructor() {
    inject(SessionService).callback()
      .then(() => this.router.navigateByUrl('/orders', { replaceUrl: true }))
      .catch(() => this.message.set('Sign-in failed verification. Please start again.'));
  }
}
