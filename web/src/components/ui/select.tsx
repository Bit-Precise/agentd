import * as React from "react";
import { cn } from "../../lib/utils";

const Select = React.forwardRef<HTMLSelectElement, React.ComponentProps<"select">>(({ className, ...props }, ref) => (
  <select className={cn("ui-select", className)} ref={ref} {...props} />
));
Select.displayName = "Select";
export { Select };
