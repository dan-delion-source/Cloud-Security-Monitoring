export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#E24B4A',
  HIGH: '#EF9F27',
  MEDIUM: '#378ADD',
  LOW: '#639922',
};

export const SEVERITY_TEXT_COLORS: Record<Severity, string> = {
  CRITICAL: 'text-[#E24B4A]',
  HIGH: 'text-[#EF9F27]',
  MEDIUM: 'text-[#378ADD]',
  LOW: 'text-[#639922]',
};

export const SEVERITY_BG_COLORS: Record<Severity, string> = {
  CRITICAL: 'bg-[#E24B4A]/10 text-[#E24B4A] border-[#E24B4A]/25',
  HIGH: 'bg-[#EF9F27]/10 text-[#EF9F27] border-[#EF9F27]/25',
  MEDIUM: 'bg-[#378ADD]/10 text-[#378ADD] border-[#378ADD]/25',
  LOW: 'bg-[#639922]/10 text-[#639922] border-[#639922]/25',
};

export const ACCENT_COLOR = '#185FA5';
