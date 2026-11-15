import * as React from "react";
import { cn } from "../../lib/utils";

export function Table({ className, ...props }: React.ComponentProps<"table">) { return <table className={cn("ui-table", className)} {...props} />; }
export function TableHeader({ className, ...props }: React.ComponentProps<"thead">) { return <thead className={cn("ui-table-header", className)} {...props} />; }
export function TableBody({ className, ...props }: React.ComponentProps<"tbody">) { return <tbody className={cn("ui-table-body", className)} {...props} />; }
export function TableRow({ className, ...props }: React.ComponentProps<"tr">) { return <tr className={cn("ui-table-row", className)} {...props} />; }
export function TableHead({ className, ...props }: React.ComponentProps<"th">) { return <th className={cn("ui-table-head", className)} {...props} />; }
export function TableCell({ className, ...props }: React.ComponentProps<"td">) { return <td className={cn("ui-table-cell", className)} {...props} />; }
