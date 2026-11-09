import type { ReactNode } from "react";

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="backdrop" onMouseDown={onClose}>
      <div className={wide ? "modal wide" : "modal"} onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-label={title}>
        <header>
          <h2>{title}</h2>
          <button className="link" onClick={onClose} aria-label="close">✕</button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
