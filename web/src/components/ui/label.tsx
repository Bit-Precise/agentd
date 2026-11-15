import * as React from "react";
import { cn } from "../../lib/utils";

const Label = React.forwardRef<HTMLLabelElement, React.ComponentProps<"label">>(({ className, ...props }, ref) => (
  <label className={cn("ui-label", className)} ref={ref} {...props} />
));
Label.displayName = "Label";
export { Label };
