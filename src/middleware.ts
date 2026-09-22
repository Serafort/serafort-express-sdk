import { SerafortClient, AuthenticationError } from '@serafort/core';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { SerafortExpressOptions } from './types.js';

function isSerafortClient(val: unknown): val is SerafortClient {
  return (
    val instanceof SerafortClient ||
    (typeof val === 'object' && val !== null && 'b2b' in val && typeof (val as any).b2b?.validateToken === 'function')
  );
}

/**
 * Creates Express authentication middleware that verifies the incoming Bearer token
 * and attaches `req.user` (UserContext) and `req.auth` to the Request.
 */
export function serafortAuth(
  clientOrOptions?: SerafortClient | SerafortExpressOptions,
  options: SerafortExpressOptions = {}
): RequestHandler {
  let client: SerafortClient;
  let opts: SerafortExpressOptions;

  if (isSerafortClient(clientOrOptions)) {
    client = clientOrOptions;
    opts = options;
  } else {
    opts = clientOrOptions || {};
    client = new SerafortClient({ endpoint: opts.endpoint || process.env.SERAFORT_ENDPOINT });
  }

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      if (opts.optional) {
        req.user = undefined;
        req.auth = undefined;
        return next();
      }

      res.status(401).json({
        status: 'error',
        error: {
          code: 'UNAUTHORIZED',
          message: 'Missing or malformed Authorization header. Expected Bearer token.',
          status: 401,
        },
      });
      return;
    }

    const token = authHeader.substring(7).trim();

    try {
      const user = await client.b2b.validateToken(token, opts.options);

      req.user = user;
      req.auth = {
        userId: user.userId,
        tenantId: user.tenantId,
        roles: user.roles,
        permissions: user.permissions,
      };

      next();
    } catch (err: unknown) {
      if (opts.optional) {
        req.user = undefined;
        req.auth = undefined;
        return next();
      }

      const status = err instanceof AuthenticationError ? err.status : 401;
      const message = err instanceof Error ? err.message : 'Invalid authorization token';
      const code = err instanceof AuthenticationError ? err.code : 'INVALID_TOKEN';

      res.status(status).json({
        status: 'error',
        error: {
          code,
          message,
          status,
        },
      });
    }
  };
}

/**
 * Express middleware guard enforcing that the authenticated user possesses a required permission.
 * Supports wildcard matching (e.g. "org:*" matches "org:read").
 */
export function requirePermission(permission: string, client?: SerafortClient): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        status: 'error',
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required before permission evaluation.',
          status: 401,
        },
      });
      return;
    }

    const hasPerm = client
      ? client.b2b.hasPermission(req.user, permission)
      : checkPermissionDirect(req.user.permissions, permission);

    if (!hasPerm) {
      res.status(403).json({
        status: 'error',
        error: {
          code: 'FORBIDDEN',
          message: `Forbidden: User lacks required permission "${permission}".`,
          status: 403,
        },
      });
      return;
    }

    next();
  };
}

/**
 * Express middleware guard enforcing that the authenticated user possesses a required role.
 */
export function requireRole(role: string): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        status: 'error',
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required before role evaluation.',
          status: 401,
        },
      });
      return;
    }

    if (!req.user.roles.includes(role)) {
      res.status(403).json({
        status: 'error',
        error: {
          code: 'FORBIDDEN',
          message: `Forbidden: User lacks required role "${role}".`,
          status: 403,
        },
      });
      return;
    }

    next();
  };
}

/**
 * Express middleware guard enforcing tenant matching.
 */
export function requireTenant(tenantResolver: string | ((req: Request) => string)): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        status: 'error',
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required before tenant evaluation.',
          status: 401,
        },
      });
      return;
    }

    const expectedTenant = typeof tenantResolver === 'function' ? tenantResolver(req) : tenantResolver;

    if (req.user.tenantId !== expectedTenant) {
      res.status(403).json({
        status: 'error',
        error: {
          code: 'TENANT_MISMATCH',
          message: 'Forbidden: Access restricted to authorized tenant.',
          status: 403,
        },
      });
      return;
    }

    next();
  };
}

function checkPermissionDirect(permissions: string[], required: string): boolean {
  if (permissions.includes('*') || permissions.includes(required)) {
    return true;
  }
  return permissions.some((perm) => {
    if (perm.endsWith(':*')) {
      const prefix = perm.slice(0, -2);
      return required.startsWith(prefix);
    }
    return false;
  });
}
