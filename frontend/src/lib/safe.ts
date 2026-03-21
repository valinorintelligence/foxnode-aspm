/**
 * Safe data access utilities to prevent runtime crashes from unexpected API data.
 */

/** Returns the value if it's an array, otherwise returns fallback (default []) */
export function safeArray<T = any>(value: unknown, fallback: T[] = []): T[] {
  return Array.isArray(value) ? value : fallback
}

/** Returns the value if it's a plain object, otherwise returns fallback (default {}) */
export function safeObj(value: unknown, fallback: Record<string, any> = {}): Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : fallback
}

/** Returns the value if it's a number, otherwise returns fallback (default 0) */
export function safeNum(value: unknown, fallback: number = 0): number {
  return typeof value === 'number' && !isNaN(value) ? value : fallback
}

/** Returns the value if it's a string, otherwise returns fallback (default '') */
export function safeStr(value: unknown, fallback: string = ''): string {
  return typeof value === 'string' ? value : fallback
}
