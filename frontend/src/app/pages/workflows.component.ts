import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';

import { ApiService } from '../core/api.service';
import { apiErrorMessage } from '../core/api-error';
import { Order, Workflow, organizationLabel } from '../core/models';

@Component({
  selector: 'app-workflows',
  imports: [DatePipe],
  template: `
    <section class="page narrow">
      <div class="eyebrow">Approvals</div>
      <h1>Order approvals</h1>
      <p class="lead">
        Submit an order for approval, request a review or cancel an outstanding request.
      </p>

      <div class="form-card">
        <label for="order">Order</label>
        <select id="order" #orderSelect (change)="selectedOrderId.set(orderSelect.value)">
          <option value="">Choose an order</option>
          @for (order of orders(); track order.id) {
            <option [value]="order.id">{{ order.id }} — {{ order.item }}</option>
          }
        </select>

        <label for="action">Action</label>
        <select id="action" #actionSelect>
          <option value="SUBMIT_FOR_APPROVAL">SUBMIT_FOR_APPROVAL</option>
          <option value="CANCEL">CANCEL</option>
          <option value="REVIEW">REVIEW</option>
        </select>

        <button
          class="primary"
          type="button"
          [disabled]="!selectedOrderId() || busy()"
          (click)="start(actionSelect.value)"
        >
          {{ busy() ? 'Submitting…' : 'Submit request' }}
        </button>
      </div>

      @if (error()) {
        <div class="callout error" role="alert">{{ error() }}</div>
      }

      @if (workflow(); as current) {
        <div class="detail-card workflow-card">
          <div class="page-heading compact">
            <div>
              <div class="eyebrow">Request {{ current.executionNumber }}</div>
              <h2>{{ current.status }}</h2>
            </div>
            <button class="secondary" type="button" (click)="refresh()">Check status</button>
          </div>
          <dl>
            <div><dt>Request ID</dt><dd class="mono">{{ current.id }}</dd></div>
            <div><dt>Order ID</dt><dd class="mono">{{ current.orderId }}</dd></div>
            <div><dt>Organisation</dt><dd>{{ accountName(current.tenantId) }}</dd></div>
            <div><dt>Requested by</dt><dd>{{ current.requestedBy }}</dd></div>
            <div><dt>Action</dt><dd>{{ current.action }}</dd></div>
            <div><dt>Created</dt><dd>{{ current.createdAt | date:'medium' }}</dd></div>
          </dl>
        </div>
      }

    </section>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class WorkflowsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly orders = signal<Order[]>([]);
  readonly selectedOrderId = signal('');
  readonly workflow = signal<Workflow | null>(null);
  readonly busy = signal(false);
  readonly error = signal('');

  readonly accountName = organizationLabel;

  ngOnInit(): void {
    this.api.listOrders().subscribe({
      next: (orders) => this.orders.set(orders),
      error: (error: unknown) => this.error.set(apiErrorMessage(error))
    });
  }

  start(action: string): void {
    const orderId = this.selectedOrderId();
    if (!orderId) {
      return;
    }

    this.busy.set(true);
    this.error.set('');
    this.api.startWorkflow(orderId, action).subscribe({
      next: (workflow) => {
        this.workflow.set(workflow);
        this.busy.set(false);
      },
      error: (error: unknown) => {
        this.error.set(apiErrorMessage(error));
        this.busy.set(false);
      }
    });
  }

  refresh(): void {
    const workflowId = this.workflow()?.id;
    if (!workflowId) {
      return;
    }
    this.error.set('');
    this.api.getWorkflow(workflowId).subscribe({
      next: (workflow) => this.workflow.set(workflow),
      error: (error: unknown) => this.error.set(apiErrorMessage(error))
    });
  }
}
