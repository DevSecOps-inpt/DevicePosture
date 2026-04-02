"use client";

import type { ReactNode } from "react";
import { ChevronDown, ChevronUp, ChevronsLeft, ChevronsRight } from "lucide-react";
import { useTableState } from "@/hooks/use-table-state";
import { cn } from "@/lib/utils";

export interface DataTableColumn<T> {
  id: string;
  header: string;
  cell: (item: T) => ReactNode;
  sortAccessor?: (item: T) => string | number;
  className?: string;
}

export function DataTable<T>({
  data,
  columns,
  getRowKey,
  onRowClick,
  emptyMessage = "No records found."
}: {
  data: T[];
  columns: DataTableColumn<T>[];
  getRowKey: (item: T) => string;
  onRowClick?: (item: T) => void;
  emptyMessage?: string;
}) {
  const { currentPage, pageCount, paginatedItems, setPage, setSortConfig, sortConfig, totalItems } = useTableState(data);

  return (
    <div className="overflow-hidden rounded-2xl border border-border">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-border text-left">
          <thead className="bg-slate-950/50">
            <tr>
              {columns.map((column) => {
                const sortable = Boolean(column.sortAccessor);
                const isSorted = sortConfig?.columnId === column.id;
                return (
                  <th key={column.id} className={cn("px-4 py-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500", column.className)}>
                    <button
                      type="button"
                      className={cn("inline-flex items-center gap-1", sortable ? "cursor-pointer text-slate-300" : "cursor-default")}
                      onClick={() => {
                        if (!column.sortAccessor) {
                          return;
                        }
                        const direction =
                          sortConfig?.columnId === column.id && sortConfig.direction === "asc" ? "desc" : "asc";
                        setSortConfig({ columnId: column.id, direction, getValue: column.sortAccessor });
                      }}
                    >
                      {column.header}
                      {sortable ? (
                        isSorted && sortConfig?.direction === "asc" ? (
                          <ChevronUp className="h-4 w-4" />
                        ) : isSorted && sortConfig?.direction === "desc" ? (
                          <ChevronDown className="h-4 w-4" />
                        ) : (
                          <ChevronDown className="h-4 w-4 opacity-40" />
                        )
                      ) : null}
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-border bg-panel/70">
            {paginatedItems.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-10 text-center text-sm text-slate-400">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              paginatedItems.map((item) => (
                <tr
                  key={getRowKey(item)}
                  className={cn("transition", onRowClick ? "cursor-pointer hover:bg-slate-900/70" : "")}
                  onClick={() => onRowClick?.(item)}
                >
                  {columns.map((column) => (
                    <td key={column.id} className={cn("px-4 py-4 text-sm text-slate-200", column.className)}>
                      {column.cell(item)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between border-t border-border bg-slate-950/40 px-4 py-3 text-sm text-slate-400">
        <span>{totalItems} total records</span>
        <div className="flex items-center gap-3">
          <span>
            Page {currentPage} of {pageCount}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded-lg border border-border p-2 text-slate-300 disabled:opacity-40"
              onClick={() => setPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
            >
              <ChevronsLeft className="h-4 w-4" />
            </button>
            <button
              type="button"
              className="rounded-lg border border-border p-2 text-slate-300 disabled:opacity-40"
              onClick={() => setPage(Math.min(pageCount, currentPage + 1))}
              disabled={currentPage === pageCount}
            >
              <ChevronsRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
