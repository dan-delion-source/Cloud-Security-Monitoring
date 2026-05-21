/**
 * Checks whether an IP address is within the private RFC 1918 subnets:
 * - 10.0.0.0/8
 * - 172.16.0.0/12
 * - 192.168.0.0/16
 * And standard local host loopbacks.
 */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  
  const trimmed = ip.trim();
  
  // Loopback and Localhost check
  if (trimmed === '127.0.0.1' || trimmed === '::1' || trimmed === 'localhost') {
    return true;
  }
  
  // IPv6 Unique Local Address (fc00::/7) or Link-Local (fe80::/10)
  if (trimmed.includes(':')) {
    const cleanIp = trimmed.toLowerCase();
    return cleanIp.startsWith('fc00') || cleanIp.startsWith('fd00') || cleanIp.startsWith('fe80');
  }
  
  // Parse IPv4
  const parts = trimmed.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) {
    return false; // Not a valid IPv4, flag as untrusted/public
  }
  
  const [p1, p2] = parts;
  
  // 10.0.0.0/8
  if (p1 === 10) return true;
  
  // 172.16.0.0/12
  if (p1 === 172 && p2 >= 16 && p2 <= 31) return true;
  
  // 192.168.0.0/16
  if (p1 === 192 && p2 === 168) return true;
  
  return false;
}

/**
 * Returns a label/route type classification based on detection rules
 */
export function getRouteTypeLabel(ruleType: string): string {
  switch (ruleType) {
    case 'public_ip': return 'Public IP';
    case 'no_vpc_endpoint': return 'No VPC endpoint';
    case 'cf_bypass': return 'CF bypass';
    case 'unauth_invoke': return 'Unauth invoke';
    default: return 'Unknown';
  }
}
