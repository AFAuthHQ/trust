import Redis from 'ioredis';
import { getConfig } from './config.js';

let client: Redis | undefined;

export function getRedis(): Redis {
  if (client) return client;
  const cfg = getConfig();
  client = new Redis(cfg.REDIS_URL, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: false,
  });
  return client;
}

export async function closeRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = undefined;
  }
}
