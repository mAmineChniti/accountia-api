import { CacheService } from '@/redis/cache.service';

describe('CacheService', () => {
  let service: CacheService;

  const redis = {
    get: jest.fn(),
    del: jest.fn(),
    setex: jest.fn(),
    scan: jest.fn(),
    unlink: jest.fn(),
    exists: jest.fn(),
    multi: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new CacheService(redis as never);
  });

  it('returns cached payload when entry is valid', async () => {
    redis.get.mockResolvedValue(
      JSON.stringify({ data: { value: 10 }, expiresAt: Date.now() + 10_000 })
    );

    await expect(service.get<{ value: number }>('k1')).resolves.toEqual({
      value: 10,
    });
  });

  it('returns undefined and deletes key when entry is expired', async () => {
    redis.get.mockResolvedValue(
      JSON.stringify({ data: { value: 10 }, expiresAt: Date.now() - 1000 })
    );

    await expect(service.get('k1')).resolves.toBeUndefined();
    expect(redis.del).toHaveBeenCalledWith('cache:k1');
  });

  it('returns undefined when JSON parsing fails', async () => {
    redis.get.mockResolvedValue('{broken-json');

    await expect(service.get('k1')).resolves.toBeUndefined();
  });

  it('persists data with setex and ttl', async () => {
    await service.set('my-key', { hello: 'world' }, 120);

    expect(redis.setex).toHaveBeenCalledTimes(1);
    const [cacheKey, ttl, payload] = redis.setex.mock.calls[0] as [
      string,
      number,
      string,
    ];
    expect(cacheKey).toBe('cache:my-key');
    expect(ttl).toBe(120);
    expect(JSON.parse(payload)).toMatchObject({ data: { hello: 'world' } });
  });

  it('delSafe ignores redis errors', async () => {
    redis.del.mockRejectedValue(new Error('redis down'));

    await expect(service.delSafe('x')).resolves.toBeUndefined();
  });

  it('deletes keys matching pattern across multiple scan pages', async () => {
    redis.scan
      .mockResolvedValueOnce(['1', ['cache:a', 'cache:b']])
      .mockResolvedValueOnce(['0', ['cache:c']]);

    await service.delPattern('tenant:*');

    expect(redis.scan).toHaveBeenCalledTimes(2);
    expect(redis.unlink).toHaveBeenCalledWith('cache:a', 'cache:b');
    expect(redis.unlink).toHaveBeenCalledWith('cache:c');
  });

  it('exists returns true only when redis returns 1', async () => {
    redis.exists.mockResolvedValueOnce(1).mockResolvedValueOnce(0);

    await expect(service.exists('yes')).resolves.toBe(true);
    await expect(service.exists('no')).resolves.toBe(false);
  });

  it('getOrSet returns cached value without calling factory', async () => {
    redis.get.mockResolvedValue(
      JSON.stringify({ data: { n: 7 }, expiresAt: Date.now() + 10_000 })
    );
    const factory = jest.fn().mockResolvedValue({ n: 99 });

    await expect(service.getOrSet('key', factory)).resolves.toEqual({ n: 7 });
    expect(factory).not.toHaveBeenCalled();
  });

  it('getOrSet executes factory and caches defined value on miss', async () => {
    redis.get.mockResolvedValue();
    const factory = jest.fn().mockResolvedValue({ n: 99 });

    await expect(service.getOrSet('key', factory, 90)).resolves.toEqual({
      n: 99,
    });
    expect(factory).toHaveBeenCalledTimes(1);
    expect(redis.setex).toHaveBeenCalledTimes(1);
  });

  it('getOrSet does not cache undefined factory results', async () => {
    redis.get.mockResolvedValue();
    const factory = jest.fn().mockResolvedValue();

    await expect(service.getOrSet('key', factory)).resolves.toBeUndefined();
    expect(redis.setex).not.toHaveBeenCalled();
  });

  it('increment returns first MULTI result value', async () => {
    const exec = jest.fn().mockResolvedValue([
      [undefined, 3],
      [undefined, 1],
    ]);
    const expire = jest.fn().mockReturnValue({ exec });
    const incr = jest.fn().mockReturnValue({ expire });
    redis.multi.mockReturnValue({ incr });

    await expect(service.increment('hits', 45)).resolves.toBe(3);

    expect(incr).toHaveBeenCalledWith('cache:counter:hits');
    expect(expire).toHaveBeenCalledWith('cache:counter:hits', 45);
  });
});
