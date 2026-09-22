# @serafort/express

Express middleware for Serafort B2B authentication, multi-tenant resolution, and local RBAC permission guards.

## Installation

```bash
npm install @serafort/express @serafort/core
```

## Usage

```typescript
import express from 'express';
import { serafortAuth, requirePermission, requireRole } from '@serafort/express';
import { SerafortClient } from '@serafort/core';

const app = express();
const client = new SerafortClient({
  endpoint: 'https://auth.acme.com',
});

// Protect all /api routes with Serafort JWT verification
app.use('/api', serafortAuth(client));

// Access user context
app.get('/api/me', (req, res) => {
  res.json({
    userId: req.user?.userId,
    tenantId: req.user?.tenantId,
    roles: req.user?.roles,
  });
});

// Enforce granular RBAC permissions (supports wildcards like "org:*")
app.post('/api/members', requirePermission('org:members:write'), (req, res) => {
  res.json({ status: 'member created' });
});

// Enforce roles
app.delete('/api/org', requireRole('admin'), (req, res) => {
  res.json({ status: 'org deleted' });
});
```
