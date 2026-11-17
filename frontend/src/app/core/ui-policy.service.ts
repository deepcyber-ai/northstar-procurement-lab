import { Injectable, inject, signal } from '@angular/core';
import { catchError, exhaustMap, of, timer } from 'rxjs';
import { ApiService, UiPolicy } from './api.service';

// A build-time pin for the immutable lab-owned widget, NOT a digest of its mutable response.
export const TRUSTED_WIDGET_INTEGRITY = 'sha384-QCSo6c2cwb9ScxwSQfPKbs5MQw/5DE4QrDDcmAdDdOQG1DeU0bx0GxT0A/vQ9X4O';
const FIXED_POLICY: UiPolicy = { xssEnabled: false, supplyChainEnabled: false, revision: '', widgetIntegrity: TRUSTED_WIDGET_INTEGRITY };

@Injectable({ providedIn: 'root' })
export class UiPolicyService {
  private readonly api = inject(ApiService);
  readonly current = signal<UiPolicy>(FIXED_POLICY);
  readonly available = signal(false);
  private unsafeContentLoaded = false;
  private reloading = false;

  constructor() {
    // This application-scoped subscription keeps watching even after the order view is left.
    // A script already executed cannot be "unexecuted" by removing its DOM element.
    timer(0, 5000).pipe(exhaustMap(() => this.api.uiPolicy().pipe(catchError(() => of(null))))).subscribe(policy => {
      const valid = policy !== null && typeof policy.xssEnabled === 'boolean'
        && typeof policy.supplyChainEnabled === 'boolean' && typeof policy.revision === 'string'
        && policy.revision.length > 0 && policy.widgetIntegrity === TRUSTED_WIDGET_INTEGRITY;
      const previous = this.current();
      const changed = !valid || previous.revision !== policy!.revision
        || previous.xssEnabled !== policy!.xssEnabled || previous.supplyChainEnabled !== policy!.supplyChainEnabled;
      this.available.set(valid);
      this.current.set(valid ? policy! : FIXED_POLICY);
      if (changed && this.unsafeContentLoaded && !this.reloading) {
        this.reloading = true;
        location.reload();
      }
    });
  }

  markUnsafeContentLoaded(): void { this.unsafeContentLoaded = true; }
}
