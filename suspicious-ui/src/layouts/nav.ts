import type { ReactElement } from "react";

export const DRAWER_WIDE = 256;
export const DRAWER_SLIM = 72;

export type NavItemConfig = {
  to: string;
  label: string;
  icon: ReactElement;
  elevatedOnly?: boolean;
};

export function filterItems(items: NavItemConfig[], isElevated: boolean) {
  return items.filter((i) => !i.elevatedOnly || isElevated);
}

export function getPageTitle(pathname: string, items: NavItemConfig[]) {
  return (
    items.find((i) => i.to !== "/" && pathname.startsWith(i.to))?.label ??
    items.find((i) => i.to === pathname)?.label ??
    "Workspace"
  );
}
