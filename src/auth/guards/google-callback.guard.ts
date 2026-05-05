import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { ExecutionContext } from '@nestjs/common';
import type { Request, Response } from 'express';

const LANG_PATTERN = /^[a-z]{2}(?:-[A-Z]{2})?$/;

const normalizeLang = (input: string | undefined): string => {
  if (!input) {
    return 'en';
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return 'en';
  }

  const [baseRaw, regionRaw] = trimmed.replace('_', '-').split('-');
  const base = (baseRaw ?? '').toLowerCase();
  const region = regionRaw ? regionRaw.toUpperCase() : undefined;
  const normalized = region ? `${base}-${region}` : base;
  return LANG_PATTERN.test(normalized) ? normalized : 'en';
};

@Injectable()
export class GoogleCallbackGuard extends AuthGuard('google') {
  override getAuthenticateOptions(): { session: false } {
    return { session: false };
  }

  override handleRequest<TUser = unknown>(
    err: unknown,
    user: TUser,
    _info: unknown,
    context: ExecutionContext
  ): TUser | undefined {
    if (err || !user) {
      const request = context.switchToHttp().getRequest<Request>();
      const response = context.switchToHttp().getResponse<Response>();

      const frontendBase = process.env.FRONTEND_URL ?? 'http://localhost:3000';
      const lang = normalizeLang(
        typeof request.query.lang === 'string' ? request.query.lang : undefined
      );

      const fallback = new URL(`/${lang}/login`, frontendBase);
      fallback.searchParams.set('oauthError', 'google_callback_failed');
      response.redirect(fallback.toString());
      return undefined;
    }

    return user;
  }
}
