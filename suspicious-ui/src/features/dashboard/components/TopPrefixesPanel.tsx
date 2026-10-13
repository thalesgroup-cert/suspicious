import { SoftCard } from "./SoftCard";
import { BarList } from "./ByTypePanel";
import { EmptyState } from "@/shared/components/EmptyState";
import type { LabelValue } from "@/features/dashboard/api";

/** Reporter names, only ever rendered for elevated users (the page omits the panel when the payload has none). */
export default function TopPrefixesPanel({ reporters }: { reporters: LabelValue[] }) {
  return (
    <SoftCard title="Top reporters" caption="Reports per person in this period">
      {reporters.length > 0 ? (
        <BarList rows={reporters} scale={reporters[0].value} ordered />
      ) : (
        <EmptyState title="No named reporters in this period" />
      )}
    </SoftCard>
  );
}
