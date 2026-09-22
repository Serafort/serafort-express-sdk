import { describe, it, expect, vi } from 'vitest';
import { serafortAuth, requirePermission, requireRole, requireTenant } from '../src/middleware.js';
import { SerafortClient } from '@serafort/core';
import type { Request, Response, NextFunction } from 'express';

describe('Express Middleware', () => {
  const mockClient = {
    b2b: {
      validateToken: vi.fn(),
      hasPermission: vi.fn(),
    },
  } as unknown as SerafortClient;

  const mockResponse = () => {
    const res: Partial<Response> = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockReturnValue(res);
    return res as Response;
  };

  describe('serafortAuth', () => {
    it('should return 401 when Authorization header is missing', async () => {
      const auth = serafortAuth(mockClient);
      const req = { headers: {} } as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      await auth(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'error',
          error: expect.objectContaining({ code: 'UNAUTHORIZED' }),
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should attach req.user and call next() on valid token', async () => {
      const mockUser = {
        userId: 'usr_123',
        tenantId: 'ten_abc',
        roles: ['admin'],
        permissions: ['read:all'],
        claims: {},
      };

      vi.mocked(mockClient.b2b.validateToken).mockResolvedValueOnce(mockUser);

      const auth = serafortAuth(mockClient);
      const req = {
        headers: { authorization: 'Bearer valid_test_token' },
      } as unknown as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      await auth(req, res, next);

      expect(req.user).toEqual(mockUser);
      expect(req.auth?.userId).toBe('usr_123');
      expect(req.auth?.tenantId).toBe('ten_abc');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should allow optional auth without failure when no header is present', async () => {
      const auth = serafortAuth(mockClient, { optional: true });
      const req = { headers: {} } as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      await auth(req, res, next);

      expect(req.user).toBeUndefined();
      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('requirePermission', () => {
    it('should call next() if user possesses permission', () => {
      const req = {
        user: {
          userId: 'u1',
          tenantId: 't1',
          roles: [],
          permissions: ['users:read', 'billing:*'],
          claims: {},
        },
      } as unknown as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      const guard = requirePermission('users:read');
      guard(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);

      // Wildcard test
      const wildcardGuard = requirePermission('billing:invoice:create');
      wildcardGuard(req, res, next);
      expect(next).toHaveBeenCalledTimes(2);
    });

    it('should return 403 if user lacks permission', () => {
      const req = {
        user: {
          userId: 'u1',
          tenantId: 't1',
          roles: [],
          permissions: ['users:read'],
          claims: {},
        },
      } as unknown as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      const guard = requirePermission('users:delete');
      guard(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    it('should enforce role requirement', () => {
      const req = {
        user: {
          userId: 'u1',
          tenantId: 't1',
          roles: ['member'],
          permissions: [],
          claims: {},
        },
      } as unknown as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      const guard = requireRole('admin');
      guard(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('requireTenant', () => {
    it('should enforce tenant isolation', () => {
      const req = {
        user: {
          userId: 'u1',
          tenantId: 'tenant-a',
          roles: [],
          permissions: [],
          claims: {},
        },
      } as unknown as Request;
      const res = mockResponse();
      const next = vi.fn() as unknown as NextFunction;

      const guard = requireTenant('tenant-b');
      guard(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });
  });
});
