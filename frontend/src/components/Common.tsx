import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

export function Button({ children, disabled, icon, onClick, variant = 'secondary' }: {
  children: ReactNode;
  disabled?: boolean;
  icon?: ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary';
}) {
  return (
    <button type="button" className={`btn ${variant === 'primary' ? 'btn-primary' : 'btn-ghost'}`} onClick={onClick} disabled={disabled}>
      {icon}
      <span>{children}</span>
    </button>
  );
}

export function Spinner() {
  return <Loader2 className="spin" size={16} />;
}
