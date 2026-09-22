import { UserContext } from '@serafort/core';
import type { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      auth?: {
        userId: string;
        tenantId: string;
        roles: string[];
        permissions: string[];
      };
      user?: UserContext;
    }
  }
}

export interface SerafortExpressOptions {
  /** Serafort IAM Base URL */
  endpoint?: string;
  /** Custom client or config */
  options?: {
    skipSignatureCheck?: boolean;
    expectedIssuer?: string;
    expectedAudience?: string;
  };
  /** If true, missing authorization headers do not fail the request (sets req.user = undefined and calls next) */
  optional?: boolean;
}
