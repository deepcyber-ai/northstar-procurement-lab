import { CurrencyPipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';

import { ApiService } from '../core/api.service';
import { apiErrorMessage } from '../core/api-error';
import { Order } from '../core/models';

@Component({
  selector: 'app-orders',
  imports: [CurrencyPipe, RouterLink],
  template: `
    <section class="page">
      <div class="page-heading">
        <div>
          <div class="eyebrow">Purchase orders</div>
          <h1>Your orders</h1>
          <p class="lead">Review current requests and follow their approval status.</p>
        </div>
        <button class="secondary" type="button" (click)="load()">Refresh</button>
      </div>

      <form (submit)="$event.preventDefault(); load()">
        <label for="order-search">Search items</label>
        <input id="order-search" #search type="search" [value]="query()"
          (input)="query.set(search.value)" maxlength="256" placeholder="Item description">
        <button class="secondary" type="submit">Search</button>
      </form>

      @if (loading()) {
        <div class="empty-state">Loading orders…</div>
      } @else if (error()) {
        <div class="callout error" role="alert">{{ error() }}</div>
      } @else if (orders().length === 0) {
        <div class="empty-state">You do not have any orders yet.</div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Order</th>
                <th>Item</th>
                <th>Requested by</th>
                <th>Status</th>
                <th>Total</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (order of orders(); track order.id) {
                <tr>
                  <td class="mono">{{ order.id }}</td>
                  <td>
                    <strong>{{ order.item }}</strong>
                    <small>Qty {{ order.quantity }} · v{{ order.version }}</small>
                  </td>
                  <td>{{ order.ownerId }}</td>
                  <td><span class="badge">{{ order.status }}</span></td>
                  <td>{{ order.quantity * order.unitPrice | currency:'GBP' }}</td>
                  <td><a class="text-link" [routerLink]="['/orders', order.id]">Open →</a></td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class OrdersComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly orders = signal<Order[]>([]);
  readonly loading = signal(true);
  readonly error = signal('');
  readonly query = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set('');
    this.api.searchOrders(this.query()).subscribe({
      next: (orders) => {
        this.orders.set(orders);
        this.loading.set(false);
      },
      error: (error: unknown) => {
        this.error.set(apiErrorMessage(error));
        this.loading.set(false);
      }
    });
  }
}
