import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { from, switchMap } from 'rxjs';

import { SessionService } from './session.service';

/**
 * DELIBERATE TRAINING WEAKNESS:
 * These identity and role headers are assembled in browser code and are therefore
 * fully attacker-controlled. The lab gateway incorrectly promotes them to
 * "trusted" upstream identity headers. Never copy this pattern into a real app.
 */
export const trainingHeadersInterceptor: HttpInterceptorFn = (request, next) => {
  if (!request.url.startsWith('/api/')) {
    return next(request);
  }

  const service = inject(SessionService);
  return from(service.accessToken()).pipe(switchMap(token => {
  const session = service.session();
  let headers = request.headers.set('X-Training-Lab', 'true');

  if (session && token) {
    headers = headers
      .set('Authorization', `Bearer ${token}`)
      .set('X-Training-User', session.user.id)
      .set('X-Training-Tenant', session.user.tenantId)
      .set('X-Training-Role', session.user.role);
  }

  return next(request.clone({ headers }));
  }));
};
