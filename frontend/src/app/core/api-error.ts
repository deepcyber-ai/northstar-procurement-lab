import { HttpErrorResponse } from '@angular/common/http';

export function apiErrorMessage(error: unknown): string {
  if (error instanceof HttpErrorResponse) {
    if (typeof error.error === 'object' && error.error !== null) {
      const body = error.error as Record<string, unknown>;
      const detail = body['message'] ?? body['error'];
      if (typeof detail === 'string') {
        return `${error.status || 'Request failed'}: ${detail}`;
      }
    }
    return `${error.status || 'Request failed'} ${error.statusText}`.trim();
  }
  return error instanceof Error ? error.message : 'Unexpected request failure';
}
