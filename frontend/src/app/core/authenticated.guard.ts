import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { SessionService } from './session.service';

/**
 * UX guard only. The Spring API remains responsible for authentication and
 * authorization; this merely keeps a visitor without a training persona from
 * landing on a page that can only return 401.
 */
export const authenticatedGuard: CanActivateFn = () => {
  const session = inject(SessionService);

  const router = inject(Router);
  return session.ready.then(() => session.isLoggedIn() || router.parseUrl('/login'));
};
