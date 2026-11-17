import { CurrencyPipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';

import { ApiService } from '../core/api.service';
import { apiErrorMessage } from '../core/api-error';
import { AdminOverview } from '../core/models';

@Component({
  selector: 'app-admin',
  imports: [CurrencyPipe],
  template: `
    <section class="page">
      <div class="page-heading">
        <div>
          <div class="eyebrow">Administration</div>
          <h1>Operations overview</h1>
          <p class="lead">A consolidated view of users, orders and approval activity.</p>
        </div>
        <button class="secondary" type="button" (click)="load()">Refresh</button>
      </div>

      @if (loading()) {
        <div class="empty-state">Loading operational data…</div>
      } @else if (error()) {
        <div class="callout error" role="alert">{{ error() }}</div>
      } @else if (overview(); as data) {
        <div class="metric-grid">
          <article><span>Active users</span><strong>{{ data.userCount }}</strong></article>
          <article><span>Purchase orders</span><strong>{{ data.orderCount }}</strong></article>
          <article><span>Approval requests</span><strong>{{ data.workflowCount }}</strong></article>
          <article><span>Order value</span><strong>{{ data.totalOrderValue | currency:'GBP' }}</strong></article>
        </div>

        <div class="detail-card summary-card">
          <div>
            <span>Reporting scope</span>
            <strong>{{ scopeLabel(data.scope) }}</strong>
          </div>
          <div>
            <span>Generated for</span>
            <strong>{{ data.generatedFor }}</strong>
          </div>
        </div>
      }
    </section>
  `,
  styles: `
    .metric-grid { display: grid; gap: 1rem; grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .metric-grid article {
      background: rgba(14, 27, 47, 0.9); border: 1px solid #2a3b58; border-radius: 0.9rem;
      display: grid; gap: 0.7rem; padding: 1.35rem;
    }
    .metric-grid span, .summary-card span { color: #8fa4be; font-size: 0.76rem; font-weight: 750; text-transform: uppercase; }
    .metric-grid strong { font-size: clamp(1.55rem, 4vw, 2.4rem); }
    .summary-card { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 1rem; }
    .summary-card div { display: grid; gap: 0.35rem; }
    @media (max-width: 800px) { .metric-grid { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 480px) { .metric-grid, .summary-card { grid-template-columns: 1fr; } }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AdminComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly overview = signal<AdminOverview | null>(null);
  readonly loading = signal(true);
  readonly error = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set('');
    this.api.getAdminOverview().subscribe({
      next: (overview) => {
        this.overview.set(overview);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.error.set(apiErrorMessage(error));
        this.loading.set(false);
      }
    });
  }

  scopeLabel(scope: string): string {
    return scope === 'all-tenants' ? 'All organisations' : 'Your organisation';
  }
}
