import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';
import { AuthService } from '@/auth/auth.service';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  override async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<
      Request & {
        googleOauthState?: string;
      }
    >();

    const mode = request.query.mode === 'register' ? 'register' : 'login';
    const rawLang =
      typeof request.query.lang === 'string' ? request.query.lang : 'en';
    const lang = rawLang.trim() || 'en';
    const redirectUri =
      typeof request.query.redirectUri === 'string'
        ? request.query.redirectUri
        : undefined;

    // Get IP address from request
    const ip =
      request.ip ??
      request.socket?.remoteAddress ??
      request.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ??
      'unknown';

    request.googleOauthState = await this.authService.buildGoogleOAuthState({
      mode,
      lang,
      redirectUri,
      ip,
    });

    const activate = await super.canActivate(context);
    return activate as boolean;
  }

  override getAuthenticateOptions(context: ExecutionContext): {
    scope: string[];
    accessType: 'offline';
    prompt: 'select_account';
    state: string;
    session: false;
  } {
    const request = context.switchToHttp().getRequest<
      Request & {
        googleOauthState?: string;
      }
    >();

    const state = request.googleOauthState;
    if (!state) {
      throw new Error('Google OAuth state was not initialized');
    }

    return {
      scope: ['email', 'profile'],
      accessType: 'offline',
      prompt: 'select_account',
      state,
      session: false,
    };
  }
}
