import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import type { Response } from 'express';

function safeStringify(obj: unknown, max = 1000) {
  try {
    const str = JSON.stringify(obj);
    if (str.length > max) return str.slice(0, max) + '...';
    return str;
  } catch {
    return '[unserializable]';
  }
}

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const maybeReq = context.switchToHttp().getRequest<unknown>();
    let method: string | undefined;
    let url: string | undefined;
    let body: unknown = undefined;
    let params: unknown = undefined;
    let query: unknown = undefined;

    if (typeof maybeReq === 'object' && maybeReq !== null) {
      const r = maybeReq as {
        method?: unknown;
        url?: unknown;
        body?: unknown;
        params?: unknown;
        query?: unknown;
      };
      method = typeof r.method === 'string' ? r.method : undefined;
      url = typeof r.url === 'string' ? r.url : undefined;
      body = r.body;
      params = r.params;
      query = r.query;
    }
    const now = Date.now();
    this.logger.log(
      `Incoming ${method ?? 'UNKNOWN'} ${url ?? 'UNKNOWN'} - body=${safeStringify(body)} params=${safeStringify(params)} query=${safeStringify(query)}`
    );

    return next.handle().pipe(
      tap((data: unknown) => {
        const res = context.switchToHttp().getResponse<Response>();
        const status: number | string =
          typeof res?.statusCode === 'number' ? res.statusCode : 'unknown';
        const ms = Date.now() - now;
        this.logger.log(
          `Response ${method ?? 'UNKNOWN'} ${url ?? 'UNKNOWN'} ${status} +${ms}ms - ${safeStringify(data)}`
        );
      })
    );
  }
}
