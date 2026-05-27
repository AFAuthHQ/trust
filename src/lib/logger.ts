import { pino, type Logger } from 'pino';
import { getConfig } from './config.js';

let cached: Logger | undefined;

export function getLogger(): Logger {
  if (cached) return cached;
  const cfg = getConfig();
  cached = pino({
    level: cfg.LOG_LEVEL,
    ...(cfg.NODE_ENV === 'development'
      ? {
          transport: {
            target: 'pino-pretty',
            options: { colorize: true, translateTime: 'HH:MM:ss' },
          },
        }
      : {}),
    base: { service: 'trust' },
  });
  return cached;
}
