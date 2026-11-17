import { Routes } from '@angular/router';

import { authenticatedGuard } from './core/authenticated.guard';

export const routes: Routes = [
  { path: 'callback', loadComponent: () => import('./pages/callback.component').then(m => m.CallbackComponent) },
  {
    path: 'login',
    loadComponent: () =>
      import('./pages/login.component').then((module) => module.LoginComponent)
  },
  {
    path: 'orders',
    canActivate: [authenticatedGuard],
    loadComponent: () =>
      import('./pages/orders.component').then((module) => module.OrdersComponent)
  },
  {
    path: 'orders/:id',
    canActivate: [authenticatedGuard],
    loadComponent: () =>
      import('./pages/order-detail.component').then(
        (module) => module.OrderDetailComponent
      )
  },
  {
    path: 'workflows',
    canActivate: [authenticatedGuard],
    loadComponent: () =>
      import('./pages/workflows.component').then(
        (module) => module.WorkflowsComponent
      )
  },
  {
    // DELIBERATE TRAINING WEAKNESS: this guard requires a session but does not
    // require the admin role; the link is merely hidden from non-admin users.
    path: 'admin',
    canActivate: [authenticatedGuard],
    loadComponent: () =>
      import('./pages/admin.component').then((module) => module.AdminComponent)
  },
  { path: '', pathMatch: 'full', redirectTo: 'login' },
  { path: '**', redirectTo: 'login' }
];
