import { HttpClient, HttpHeaders } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';

import {
  AdminOverview,
  Order,
  OrderListEnvelope,
  Workflow
} from './models';

export interface UiPolicy {
  xssEnabled: boolean;
  supplyChainEnabled: boolean;
  revision: string;
  widgetIntegrity: string;
}
export interface OrderNotes { orderId: string; html: string; }
export interface ExportResult { output: string; exitCode: number; timedOut: boolean; }

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api';

  listOrders(): Observable<Order[]> {
    return this.http
      .get<Order[] | OrderListEnvelope>(`${this.baseUrl}/orders`)
      .pipe(map((response) => (Array.isArray(response) ? response : response.orders)));
  }

  getOrder(orderId: string): Observable<Order> {
    return this.http.get<Order>(
      `${this.baseUrl}/orders/${encodeURIComponent(orderId)}`
    );
  }

  searchOrders(q: string): Observable<Order[]> {
    return this.http.get<Order[]>(`${this.baseUrl}/orders/search`, { params: { q } });
  }

  submitOrder(orderId: string): Observable<{ updated: number }> {
    return this.http.post<{ updated: number }>(`${this.baseUrl}/orders/submit`, { orderId });
  }

  uiPolicy(): Observable<UiPolicy> {
    return this.http.get<UiPolicy>(`${this.baseUrl}/ui-policy`);
  }

  getNotes(orderId: string): Observable<OrderNotes> {
    return this.http.get<OrderNotes>(`${this.baseUrl}/orders/${encodeURIComponent(orderId)}/notes`);
  }

  saveNotes(orderId: string, html: string): Observable<OrderNotes> {
    return this.http.put<OrderNotes>(`${this.baseUrl}/orders/${encodeURIComponent(orderId)}/notes`, { html });
  }

  exportOrder(orderId: string, format: string): Observable<ExportResult> {
    return this.http.post<ExportResult>(`${this.baseUrl}/orders/${encodeURIComponent(orderId)}/export`, { format });
  }

  getAdminOverview(): Observable<AdminOverview> {
    return this.http.get<AdminOverview>(`${this.baseUrl}/admin/overview`);
  }

  startWorkflow(orderId: string, action: string): Observable<Workflow> {
    const idempotencyKey = `ui-${orderId}-${Date.now()}`;
    return this.http.post<Workflow>(
      `${this.baseUrl}/workflows`,
      { orderId, action },
      { headers: new HttpHeaders({ 'Idempotency-Key': idempotencyKey }) }
    );
  }

  getWorkflow(workflowId: string): Observable<Workflow> {
    return this.http.get<Workflow>(
      `${this.baseUrl}/workflows/${encodeURIComponent(workflowId)}`
    );
  }
}
