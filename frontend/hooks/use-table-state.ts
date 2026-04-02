"use client";

import { useMemo, useState } from "react";

export interface SortConfig<T> {
  columnId: string;
  direction: "asc" | "desc";
  getValue: (item: T) => string | number;
}

export function useTableState<T>(items: T[], initialPageSize = 8) {
  const [page, setPage] = useState(1);
  const [sortConfig, setSortConfig] = useState<SortConfig<T> | null>(null);

  const sortedItems = useMemo(() => {
    if (!sortConfig) {
      return items;
    }

    return [...items].sort((left, right) => {
      const a = sortConfig.getValue(left);
      const b = sortConfig.getValue(right);

      if (a < b) {
        return sortConfig.direction === "asc" ? -1 : 1;
      }
      if (a > b) {
        return sortConfig.direction === "asc" ? 1 : -1;
      }
      return 0;
    });
  }, [items, sortConfig]);

  const pageCount = Math.max(1, Math.ceil(sortedItems.length / initialPageSize));
  const currentPage = Math.min(page, pageCount);
  const paginatedItems = sortedItems.slice((currentPage - 1) * initialPageSize, currentPage * initialPageSize);

  return {
    currentPage,
    pageCount,
    paginatedItems,
    setPage,
    setSortConfig,
    sortConfig,
    totalItems: sortedItems.length
  };
}
