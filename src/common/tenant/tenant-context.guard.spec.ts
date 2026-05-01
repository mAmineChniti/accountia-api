import { BadRequestException, type ExecutionContext } from '@nestjs/common';
import { Types } from 'mongoose';
import { TenantContextGuard } from './tenant-context.guard';
import { type TenantContextService } from './tenant-context.service';
import { Role } from '@/auth/enums/role.enum';

describe('TenantContextGuard', () => {
  const tenantContextService = {
    resolveTenantContext: jest.fn(),
    resolveUserBusinessId: jest.fn(),
  } as unknown as jest.Mocked<TenantContextService>;
  let guard: TenantContextGuard;

  const validBusinessId = new Types.ObjectId().toHexString();

  const buildContext = (request: Record<string, unknown>): ExecutionContext =>
    ({
      switchToHttp: () => ({ getRequest: () => request }),
    }) as unknown as ExecutionContext;

  beforeEach(() => {
    jest.clearAllMocks();
    guard = new TenantContextGuard(tenantContextService);
  });

  it('throws Unauthorized when user is missing', async () => {
    await expect(
      guard.canActivate(buildContext({ method: 'GET', path: '/x', query: {} }))
    ).rejects.toThrow(/User context is missing/);
  });

  it('reads businessId from query for GET requests', async () => {
    (tenantContextService.resolveTenantContext as jest.Mock).mockResolvedValue({
      businessId: validBusinessId,
      databaseName: 'db',
      membershipRole: 'OWNER',
    });

    const req = {
      method: 'GET',
      path: '/expenses',
      url: '/expenses',
      query: { businessId: validBusinessId },
      user: { id: 'u1', role: Role.CLIENT },
    };

    await expect(guard.canActivate(buildContext(req))).resolves.toBe(true);
    expect(tenantContextService.resolveTenantContext).toHaveBeenCalledWith(
      req.user,
      validBusinessId
    );
  });

  it('reads businessId from body for POST requests', async () => {
    (tenantContextService.resolveTenantContext as jest.Mock).mockResolvedValue({
      businessId: validBusinessId,
      databaseName: 'db',
      membershipRole: 'MEMBER',
    });

    const req = {
      method: 'POST',
      path: '/expenses',
      url: '/expenses',
      body: { businessId: validBusinessId },
      query: {},
      user: { id: 'u1', role: Role.CLIENT },
    };

    await expect(guard.canActivate(buildContext(req))).resolves.toBe(true);
  });

  it('auto-resolves businessId from membership when missing on POST', async () => {
    (tenantContextService.resolveUserBusinessId as jest.Mock).mockResolvedValue(
      validBusinessId
    );
    (tenantContextService.resolveTenantContext as jest.Mock).mockResolvedValue({
      businessId: validBusinessId,
      databaseName: 'db',
      membershipRole: 'OWNER',
    });

    const req = {
      method: 'POST',
      path: '/expenses/extract-receipt',
      url: '/expenses/extract-receipt',
      body: {},
      query: {},
      user: { id: 'u1', role: Role.CLIENT },
    };

    await expect(guard.canActivate(buildContext(req))).resolves.toBe(true);
    expect(tenantContextService.resolveUserBusinessId).toHaveBeenCalledWith(
      'u1'
    );
    expect(tenantContextService.resolveTenantContext).toHaveBeenCalledWith(
      req.user,
      validBusinessId
    );
  });

  it('throws when no businessId and user has no membership', async () => {
    (tenantContextService.resolveUserBusinessId as jest.Mock).mockResolvedValue(
      null
    );

    const req = {
      method: 'POST',
      path: '/expenses',
      url: '/expenses',
      body: {},
      query: {},
      user: { id: 'u1', role: Role.CLIENT },
    };

    await expect(guard.canActivate(buildContext(req))).rejects.toThrow(
      BadRequestException
    );
  });

  it('lets platform users through without a businessId', async () => {
    const req = {
      method: 'POST',
      path: '/expenses',
      url: '/expenses',
      body: {},
      query: {},
      user: { id: 'u1', role: Role.PLATFORM_ADMIN },
    } as Record<string, unknown> & { tenant?: unknown };

    await expect(guard.canActivate(buildContext(req))).resolves.toBe(true);
    expect(req.tenant).toEqual({
      businessId: '',
      databaseName: '',
      membershipRole: 'platform-admin',
    });
    expect(tenantContextService.resolveUserBusinessId).not.toHaveBeenCalled();
  });

  it('rejects an invalid ObjectId', async () => {
    const req = {
      method: 'POST',
      path: '/expenses',
      url: '/expenses',
      body: { businessId: 'not-an-objectid' },
      query: {},
      user: { id: 'u1', role: Role.CLIENT },
    };

    await expect(guard.canActivate(buildContext(req))).rejects.toThrow(
      /Invalid businessId/
    );
  });
});
