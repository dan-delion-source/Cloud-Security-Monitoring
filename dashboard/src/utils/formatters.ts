/**
 * Formats a date string into standard security timestamp: YYYY-MM-DD HH:mm:ss UTC
 */
export function formatDateUTC(dateStr: string | Date | null): string {
  if (!dateStr) return 'N/A';
  
  const d = typeof dateStr === 'string' ? new Date(dateStr) : dateStr;
  if (isNaN(d.getTime())) return 'N/A';
  
  const pad = (n: number) => String(n).padStart(2, '0');
  
  const year = d.getUTCFullYear();
  const month = pad(d.getUTCMonth() + 1);
  const day = pad(d.getUTCDate());
  const hours = pad(d.getUTCHours());
  const minutes = pad(d.getUTCMinutes());
  const seconds = pad(d.getUTCSeconds());
  
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
}

/**
 * Formats a date string relative to current time (e.g., "5m ago", "2h ago", "12d ago")
 */
export function formatDateRelative(dateStr: string | Date | null): string {
  if (!dateStr) return 'N/A';
  
  const d = typeof dateStr === 'string' ? new Date(dateStr) : dateStr;
  if (isNaN(d.getTime())) return 'N/A';
  
  const diffMs = Date.now() - d.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);
  
  if (diffSec < 60) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  return `${diffDay}d ago`;
}

/**
 * Rounds any floating number to the nearest integer to avoid layout and precision artifacts.
 */
export function roundNumber(val: number): number {
  return Math.round(val);
}

/**
 * Formats a fraction card value cleanly, e.g. "3/5"
 */
export function formatFraction(numerator: number, denominator: number): string {
  return `${roundNumber(numerator)}/${roundNumber(denominator)}`;
}

/**
 * Formats a rate percentage, e.g. "60%"
 */
export function formatPercentage(numerator: number, denominator: number): string {
  if (denominator === 0) return '0%';
  return `${roundNumber((numerator / denominator) * 100)}%`;
}
