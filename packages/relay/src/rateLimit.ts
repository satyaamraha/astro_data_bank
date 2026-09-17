/**
 * Fixed-window rate limiter.
 *
 * Crude on purpose. The relay's abuse defence cannot depend on knowing who is
 * sending (sealed sender removes that), so it falls back to per-IP limits plus
 * hard size and queue caps. This is the honest state of the art for anonymous
 * submission, and it is why the design notes flag blind delivery tokens as the
 * real fix.
 *
 * The bucket map is itself bounded, because otherwise a spray of forged source
 * addresses would turn the limiter into a memory leak — the exact failure the
 * limiter exists to prevent.
 */

const MAX_TRACKED_KEYS = 100_000;

interface Bucket {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  allow(key: string): boolean {
    const timestamp = this.now();
    const bucket = this.buckets.get(key);

    if (!bucket || timestamp - bucket.windowStart >= this.windowMs) {
      if (this.buckets.size >= MAX_TRACKED_KEYS) this.evictStale(timestamp);
      this.buckets.set(key, { count: 1, windowStart: timestamp });
      return true;
    }

    if (bucket.count >= this.limit) return false;
    bucket.count += 1;
    return true;
  }

  private evictStale(timestamp: number): void {
    for (const [key, bucket] of this.buckets) {
      if (timestamp - bucket.windowStart >= this.windowMs) this.buckets.delete(key);
    }
    // If every bucket is live, drop the oldest rather than growing without
    // bound. Under that much load some legitimate traffic is refused anyway.
    if (this.buckets.size >= MAX_TRACKED_KEYS) {
      const oldest = [...this.buckets.entries()].sort(
        (a, b) => a[1].windowStart - b[1].windowStart,
      );
      for (const [key] of oldest.slice(0, Math.floor(MAX_TRACKED_KEYS / 10))) {
        this.buckets.delete(key);
      }
    }
  }

  get trackedKeys(): number {
    return this.buckets.size;
  }
}
