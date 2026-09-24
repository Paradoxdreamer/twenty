import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';

import { addMilliseconds } from 'date-fns';
import ms from 'ms';

import { type AuthToken } from 'src/engine/core-modules/auth/dto/auth-token.dto';
import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { type LoginTokenJwtPayload } from 'src/engine/core-modules/auth/types/login-token-jwt-payload.type';
import { JwtTokenTypeEnum } from 'src/engine/core-modules/auth/types/jwt-token-type.enum';
import { JwtWrapperService } from 'src/engine/core-modules/jwt/services/jwt-wrapper.service';
import { TwentyConfigService } from 'src/engine/core-modules/twenty-config/twenty-config.service';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';
import { CacheStorageService } from 'src/engine/core-modules/cache-storage/services/cache-storage.service';
import { InjectCacheStorage } from 'src/engine/core-modules/cache-storage/decorators/inject-cache-storage.decorator';
import { CacheStorageNamespace } from 'src/engine/core-modules/cache-storage/types/cache-storage-namespace.enum';

@Injectable()
export class LoginTokenService {
  constructor(
    private readonly jwtWrapperService: JwtWrapperService,
    private readonly twentyConfigService: TwentyConfigService,
    @InjectCacheStorage(CacheStorageNamespace.EngineAuthSession)
    private readonly cacheStorageService: CacheStorageService,
  ) {}

  async generateLoginToken(
    email: string,
    workspaceId: string,
    authProvider: AuthProviderEnum,
    options?: { impersonatorUserWorkspaceId?: string },
  ): Promise<AuthToken> {
    if (!Object.values(AuthProviderEnum).includes(authProvider)) {
      throw new AuthException(
        'Authentication provider is required to generate a login token',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    const jti = randomUUID();

    const jwtPayload: LoginTokenJwtPayload = {
      type: JwtTokenTypeEnum.LOGIN,
      sub: email,
      workspaceId,
      authProvider,
      impersonatorUserWorkspaceId: options?.impersonatorUserWorkspaceId,
      jti,
    };

    const expiresIn = this.twentyConfigService.get('LOGIN_TOKEN_EXPIRES_IN');

    const expiresAt = addMilliseconds(new Date().getTime(), ms(expiresIn));

    return {
      token: await this.jwtWrapperService.signAsyncOrThrow(jwtPayload, {
        expiresIn,
      }),
      expiresAt,
    };
  }

  async verifyLoginToken(loginToken: string): Promise<LoginTokenJwtPayload> {
    await this.jwtWrapperService.verifyJwtToken(loginToken);

    const decoded = this.jwtWrapperService.decode<LoginTokenJwtPayload>(
      loginToken,
      { json: true },
    );

    if (decoded.type !== JwtTokenTypeEnum.LOGIN) {
      throw new AuthException(
        'Expected a login token',
        AuthExceptionCode.INVALID_JWT_TOKEN_TYPE,
      );
    }

    if (!Object.values(AuthProviderEnum).includes(decoded.authProvider)) {
      throw new AuthException(
        'Login token has an invalid authentication provider',
        AuthExceptionCode.UNAUTHENTICATED,
      );
    }

    if (!decoded.jti) {
      // Backward compatibility: tokens issued before this change have no jti.
      // They remain valid until natural expiry, but new tokens are single-use.
      return decoded;
    }

    return decoded;
  }

  /**
   * Atomically consume a login token so it can only be exchanged once.
   * Uses Redis SET NX (or in-memory equivalent) with TTL matching remaining lifetime.
   */
  async consumeLoginTokenOrThrow(payload: LoginTokenJwtPayload): Promise<void> {
    if (!payload.jti) {
      // Legacy tokens without jti cannot be single-use enforced.
      return;
    }

    const key = `login-token:jti:${payload.jti}`;

    // TTL: use configured expiry as upper bound (token already verified).
    const expiresIn = this.twentyConfigService.get('LOGIN_TOKEN_EXPIRES_IN');
    const ttlMs = ms(expiresIn);

    const acquired = await this.cacheStorageService.setIfAbsent(
      key,
      true,
      ttlMs,
    );

    if (!acquired) {
      throw new AuthException(
        'Login token has already been used',
        AuthExceptionCode.UNAUTHENTICATED,
      );
    }
  }
}
