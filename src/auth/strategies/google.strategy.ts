import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import type { Request } from 'express';
import { Profile, Strategy } from 'passport-google-oauth20';

export type GoogleAuthUser = {
  email: string;
  given_name?: string;
  family_name?: string;
  name?: string;
  picture?: string;
  state?: string;
};

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly configService: ConfigService) {
    const clientID = configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = configService.get<string>('GOOGLE_CLIENT_SECRET');
    const callbackURL = configService.get<string>('GOOGLE_CALLBACK_URL');

    if (!clientID || !clientSecret || !callbackURL) {
      throw new InternalServerErrorException(
        'Google OAuth is not configured on the server'
      );
    }

    super({
      clientID,
      clientSecret,
      callbackURL,
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  validate(
    req: Request,
    _accessToken: string,
    _refreshToken: string,
    profile: Profile
  ): GoogleAuthUser {
    const email = profile.emails?.[0]?.value;
    if (!email) {
      throw new UnauthorizedException('Google account email is missing');
    }

    const state =
      typeof req.query.state === 'string' ? req.query.state : undefined;

    return {
      email,
      given_name: profile.name?.givenName,
      family_name: profile.name?.familyName,
      name: profile.displayName,
      picture: profile.photos?.[0]?.value,
      state,
    };
  }
}
