import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { SessionService } from './core/session.service';

@Component({
  selector: 'app-root',
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppComponent {
  private readonly router = inject(Router);
  readonly session = inject(SessionService);

  logout(): void {
    void this.session.logout().catch(() => window.alert('Sign-out could not complete. Please retry.'));
  }
}
