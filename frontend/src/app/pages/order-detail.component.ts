import { CurrencyPipe, DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, afterRenderEffect, computed, inject, signal } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { ActivatedRoute, RouterLink } from '@angular/router';

import { ApiService } from '../core/api.service';
import { apiErrorMessage } from '../core/api-error';
import { Order, organizationLabel } from '../core/models';
import { TRUSTED_WIDGET_INTEGRITY, UiPolicyService } from '../core/ui-policy.service';

@Component({
  selector: 'app-order-detail',
  imports: [CurrencyPipe, RouterLink],
  template: `
    <section class="page narrow">
      <a class="back-link" routerLink="/orders">← Back to orders</a>

      @if (loading()) {
        <div class="empty-state">Loading order…</div>
      } @else if (error()) {
        <div class="callout error" role="alert">{{ error() }}</div>
      } @else if (order(); as current) {
        <div class="eyebrow">Purchase order</div>
        <h1>{{ current.item }}</h1>
        <div class="detail-card">
          <dl>
            <div><dt>Order ID</dt><dd class="mono">{{ current.id }}</dd></div>
            <div><dt>Organisation</dt><dd>{{ accountName(current.tenantId) }}</dd></div>
            <div><dt>Requested by</dt><dd>{{ current.ownerId }}</dd></div>
            <div><dt>Status</dt><dd><span class="badge">{{ current.status }}</span></dd></div>
            <div><dt>Quantity</dt><dd>{{ current.quantity }}</dd></div>
            <div><dt>Unit price</dt><dd>{{ current.unitPrice | currency:'GBP' }}</dd></div>
            <div><dt>Approval runs</dt><dd>{{ current.workflowStarts }}</dd></div>
            <div><dt>Revision</dt><dd>{{ current.version }}</dd></div>
          </dl>
          <a class="primary action-link" routerLink="/workflows">Manage approval</a>
          @if (current.status === 'DRAFT') {
            <button class="secondary" type="button" [disabled]="submitting()" (click)="submit()">
              Submit order for approval
            </button>
          }
          @if (submissionMessage()) {
            <p role="status">{{ submissionMessage() }}</p>
          }
        </div>

        <section class="form-card" aria-labelledby="notes-heading">
          <h2 id="notes-heading">Purchasing notes</h2>
          <p class="lead">Delivery instructions and supporting information for your purchasing team.</p>
          @if (notesLoaded()) {
            <div class="notes-preview" data-testid="purchasing-notes" [innerHTML]="renderedNotes()"></div>
            <label for="purchasing-notes">Edit formatted notes</label>
            <textarea id="purchasing-notes" rows="5" maxlength="8192" [value]="notesDraft()"
              (input)="notesDraft.set($any($event.target).value)"></textarea>
            <small>Basic HTML formatting is supported.</small>
            <button class="secondary" type="button" [disabled]="savingNotes()" (click)="saveNotes()">Save notes</button>
          }
          @if (notesMessage()) { <p role="status">{{ notesMessage() }}</p> }
        </section>

        <section class="form-card" aria-labelledby="export-heading">
          <h2 id="export-heading">Export purchase order</h2>
          <label for="export-format">Export format</label>
          <input id="export-format" type="text" maxlength="128" [value]="exportFormat()"
            (input)="exportFormat.set($any($event.target).value)" placeholder="csv">
          <small>Available formats: csv, json.</small>
          <button class="secondary" type="button" [disabled]="exporting()" (click)="exportOrder()">Generate export</button>
          @if (exportMessage()) { <p role="status">{{ exportMessage() }}</p> }
          @if (exportOutput()) { <pre class="export-output" tabindex="0">{{ exportOutput() }}</pre> }
        </section>
      }
      <section class="form-card" [hidden]="!order()" aria-labelledby="supplier-heading">
        <h2 id="supplier-heading">Supplier delivery information</h2>
        <div id="northstar-supplier-widget">Supplier information is unavailable.</div>
      </section>
    </section>
  `,
  styles: `
    textarea, input { background: #09172a; border: 1px solid #354763; border-radius: .5rem;
      color: #edf7ff; font: inherit; padding: .72rem; width: 100%; }
    textarea:focus-visible, input:focus-visible { outline: 3px solid rgba(99,229,212,.45); outline-offset: 2px; }
    .notes-preview { border-bottom: 1px solid #263651; overflow-wrap: anywhere; padding-bottom: 1rem; }
    .export-output { background: #09172a; overflow: auto; padding: 1rem; white-space: pre-wrap; }
    small { color: #aebed2; }
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class OrderDetailComponent implements OnInit, OnDestroy {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly document = inject(DOCUMENT);
  private readonly policy = inject(UiPolicyService);
  private widgetScript?: HTMLScriptElement;
  private widgetKey = '';

  readonly order = signal<Order | null>(null);
  readonly loading = signal(true);
  readonly error = signal('');
  readonly submitting = signal(false);
  readonly submissionMessage = signal('');
  readonly notesHtml = signal('');
  readonly notesDraft = signal('');
  readonly notesLoaded = signal(false);
  readonly notesMessage = signal('');
  readonly savingNotes = signal(false);
  readonly exportFormat = signal('csv');
  readonly exporting = signal(false);
  readonly exportOutput = signal('');
  readonly exportMessage = signal('');
  readonly renderedNotes = computed(() => {
    if (this.policy.available() && this.policy.current().xssEnabled) {
      this.policy.markUnsafeContentLoaded();
      // DELIBERATE XSS-01: trusting user-authored HTML bypasses Angular's sanitization.
      // This is application misuse, not an Angular defect. Fixed mode returns a plain string.
      return this.sanitizer.bypassSecurityTrustHtml(this.notesHtml());
    }
    return this.notesHtml();
  });

  constructor() {
    afterRenderEffect(() => {
      const current = this.order();
      const policy = this.policy.current();
      const host = this.document.getElementById('northstar-supplier-widget');
      if (!current || !host || !this.policy.available()) {
        this.widgetScript?.remove();
        this.widgetKey = '';
        if (host) host.textContent = 'Supplier information is unavailable.';
        return;
      }
      const key = `${current.id}:${policy.revision}:${policy.supplyChainEnabled}`;
      if (key === this.widgetKey) return;
      this.widgetKey = key;
      this.widgetScript?.remove();
      host.textContent = 'Loading supplier information…';
      const script = this.document.createElement('script');
      script.src = `/api/vendor/widget.js?revision=${encodeURIComponent(policy.revision)}`;
      script.async = true;
      if (policy.supplyChainEnabled) {
        // DELIBERATE SC-01: mutable lab-owned supplier JavaScript is trusted without integrity.
        this.policy.markUnsafeContentLoaded();
      } else {
        script.integrity = TRUSTED_WIDGET_INTEGRITY;
        script.crossOrigin = 'anonymous';
      }
      script.onerror = () => { host.textContent = 'Supplier information could not be verified. Please contact procurement support.'; };
      this.widgetScript = script;
      this.document.body.appendChild(script);
    });
  }

  ngOnDestroy(): void { this.widgetScript?.remove(); }

  saveNotes(): void {
    const current = this.order();
    if (!current || this.savingNotes()) return;
    this.savingNotes.set(true);
    this.api.saveNotes(current.id, this.notesDraft()).subscribe({
      next: notes => { this.notesHtml.set(notes.html); this.notesMessage.set('Notes saved.'); this.savingNotes.set(false); },
      error: (error: unknown) => { this.notesMessage.set(apiErrorMessage(error)); this.savingNotes.set(false); }
    });
  }

  exportOrder(): void {
    const current = this.order();
    if (!current || this.exporting()) return;
    this.exporting.set(true);
    this.exportOutput.set('');
    this.exportMessage.set('Generating export…');
    this.api.exportOrder(current.id, this.exportFormat()).subscribe({
      next: result => {
        this.exporting.set(false);
        this.exportOutput.set(result.output);
        this.exportMessage.set(result.timedOut ? 'Export timed out.' : result.exitCode === 0 ? 'Export ready.' : 'Export could not be completed.');
      },
      error: (error: unknown) => { this.exporting.set(false); this.exportMessage.set(apiErrorMessage(error)); }
    });
  }

  submit(): void {
    const current = this.order();
    if (!current || this.submitting()) return;
    this.submitting.set(true);
    this.api.submitOrder(current.id).subscribe({
      next: (result) => {
        this.submitting.set(false);
        this.submissionMessage.set(result.updated ? 'Order submitted.' : 'No eligible order was updated.');
        if (result.updated) this.order.set({ ...current, status: 'PENDING_APPROVAL', version: current.version + 1 });
      },
      error: (error: unknown) => {
        this.submitting.set(false);
        this.submissionMessage.set(apiErrorMessage(error));
      }
    });
  }

  readonly accountName = organizationLabel;

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (!id) {
      this.error.set('No order ID was supplied.');
      this.loading.set(false);
      return;
    }

    this.api.getOrder(id).subscribe({
      next: (order) => {
        this.order.set(order);
        this.loading.set(false);
        this.api.getNotes(order.id).subscribe({
          next: notes => { this.notesHtml.set(notes.html); this.notesDraft.set(notes.html); this.notesLoaded.set(true); },
          error: (error: unknown) => this.notesMessage.set(apiErrorMessage(error))
        });
      },
      error: (error: unknown) => {
        this.error.set(apiErrorMessage(error));
        this.loading.set(false);
      }
    });
  }
}
