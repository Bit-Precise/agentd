import type { ReactNode } from "react";
import { Dialog, DialogContent, DialogTitle } from "./ui/dialog";

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className={wide ? "wide" : undefined} aria-label={title}>
        <header>
          <DialogTitle>{title}</DialogTitle>
        </header>
        <div className="modal-body">{children}</div>
      </DialogContent>
    </Dialog>
  );
}
