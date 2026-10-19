import * as React from "react";
import {
  Box,
  Container,
  FormControl,
  IconButton,
  InputLabel,
  LinearProgress,
  MenuItem,
  Select,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { RefreshOutlined } from "@mui/icons-material";
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import {
  getCampaignSummary,
  getMailVolume,
  getNeighbours,
  getPca,
} from "@/features/campaigns/api";
import { SoftCard } from "@/features/dashboard/components/SoftCard";
import { fieldLabelSx } from "@/features/dashboard/format";
import { EmptyState } from "@/shared/components/EmptyState";
import { PanelState } from "@/features/campaigns/components/PanelState";
import CampaignKpis from "@/features/campaigns/components/CampaignKpis";
import CampaignTable from "@/features/campaigns/components/CampaignTable";
import EmbeddingMap from "@/features/campaigns/components/EmbeddingMap";
import MixBar from "@/features/campaigns/components/MixBar";
import SidePanel from "@/features/campaigns/components/SidePanel";
import ScrollRegion from "@/features/campaigns/components/ScrollRegion";
import VolumeChart from "@/features/campaigns/components/VolumeChart";

const PERIODS = [7, 15, 30, 90] as const;
// The backend's own default sample size for the map and the neighbour lists.
const SAMPLE = 1500;

export default function CampaignsPage() {
  const theme = useTheme();
  const [days, setDays] = React.useState<number>(15);
  const [selectedCaseIds, setSelectedCaseIds] = React.useState<string[]>([]);
  const mapRef = React.useRef<HTMLDivElement>(null);

  // Independent queries: a slow PCA never holds back the indicators, and one failure stays in its panel.
  const summaryQuery = useQuery({
    queryKey: ["campaigns", "summary", days],
    queryFn: () => getCampaignSummary(days),
    retry: false,
    placeholderData: keepPreviousData,
  });
  const volumeQuery = useQuery({
    queryKey: ["campaigns", "volume", days],
    queryFn: () => getMailVolume(days),
    retry: false,
    placeholderData: keepPreviousData,
  });
  const pcaQuery = useQuery({ queryKey: ["campaigns", "pca", SAMPLE], queryFn: () => getPca(SAMPLE), retry: false });
  const neighboursQuery = useQuery({
    queryKey: ["campaigns", "neighbours", SAMPLE],
    queryFn: () => getNeighbours(SAMPLE),
    retry: false,
  });

  const refresh = () => {
    summaryQuery.refetch();
    volumeQuery.refetch();
    pcaQuery.refetch();
    neighboursQuery.refetch();
  };

  const showInMap = (ids: string[]) => {
    setSelectedCaseIds(ids);
    if (ids.length) {
      const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      mapRef.current?.scrollIntoView?.({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    }
  };

  // keepPreviousData shows the old period while the new one loads: say so.
  const switching =
    (summaryQuery.isFetching && summaryQuery.isPlaceholderData) || (volumeQuery.isFetching && volumeQuery.isPlaceholderData);
  const isEmpty = summaryQuery.data?.messages === 0;

  return (
    <Box>
      <Box sx={{ position: "sticky", top: 0, zIndex: 20, borderBottom: "1px solid", borderColor: "divider", backdropFilter: "blur(14px)" }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          spacing={1.5}
          sx={{ px: { xs: 2, md: 3 }, py: 1.5, alignItems: { md: "center" }, justifyContent: "space-between" }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="pageTitle" component="h1">
              Campaigns
            </Typography>
            <Typography variant="subtitle2" color="text.secondary" component="p">
              Organisation-wide, from the message store.
            </Typography>
            <Typography variant="caption" color="text.secondary" component="p">
              Campaign = messages sharing the same source references (inferred).
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel id="campaigns-period-label" sx={fieldLabelSx(theme.palette)}>
                Period
              </InputLabel>
              <Select
                labelId="campaigns-period-label"
                label="Period"
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              >
                {PERIODS.map((d) => (
                  <MenuItem key={d} value={d}>
                    Last {d} days
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <Tooltip title="Refresh">
              <IconButton aria-label="Refresh" onClick={refresh} sx={{ borderRadius: 2, border: "1px solid", borderColor: "divider" }}>
                <RefreshOutlined />
              </IconButton>
            </Tooltip>
          </Stack>
        </Stack>
      </Box>

      {switching ? <LinearProgress aria-label={`Loading the last ${days} days`} sx={{ height: 2 }} /> : null}

      <Container maxWidth="xl" sx={{ py: 2.5 }}>
        {isEmpty ? (
          <Box aria-busy={switching} sx={{ py: 8, opacity: switching ? 0.6 : 1 }}>
            <EmptyState title="No messages in this period." hint={`The message store has no mail dated in the last ${days} days.`} />
          </Box>
        ) : (
          <Stack spacing={2} aria-busy={switching} sx={{ opacity: switching ? 0.6 : 1, transition: "opacity .2s ease" }}>
            <PanelState query={summaryQuery} what="the indicators" height={120}>
              {(s) => <CampaignKpis summary={s} />}
            </PanelState>

            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "2fr 1fr" }, gap: 2 }}>
              <Box ref={mapRef} sx={{ minWidth: 0, scrollMarginTop: 96 }}>
                <SoftCard title="Embedding map">
                  <PanelState query={pcaQuery} what="the embedding map" height={360}>
                    {(pca) => (
                      <EmbeddingMap
                        points={pca.points}
                        explainedVariance={pca.explained_variance}
                        campaigns={summaryQuery.data?.campaigns}
                        neighbours={neighboursQuery.data}
                        sampleLimit={SAMPLE}
                        selectedCaseIds={selectedCaseIds}
                        onSelectCases={setSelectedCaseIds}
                      />
                    )}
                  </PanelState>
                </SoftCard>
              </Box>
              <SoftCard title="Messages to review" sx={{ minWidth: 0 }} fillHeight>
                <PanelState query={neighboursQuery} what="the review lists" height={240}>
                  {(n) => (
                    // On desktop the map sets the row height and the lists scroll inside it, instead of
                    // stretching the row and leaving a hole under the map.
                    <Box sx={{ position: { md: "relative" }, flex: 1, minHeight: { md: 240 } }}>
                      <ScrollRegion label="Review lists" sx={{ position: { md: "absolute" }, inset: 0, overflowY: { md: "auto" }, pr: { md: 1 } }}>
                        <SidePanel
                          neighbours={n}
                          onSelectCases={showInMap}
                          points={pcaQuery.data?.points}
                          selectedCaseIds={selectedCaseIds}
                          campaigns={summaryQuery.data?.campaigns}
                        />
                      </ScrollRegion>
                    </Box>
                  )}
                </PanelState>
              </SoftCard>
            </Box>

            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "2fr 1fr" }, gap: 2, alignItems: "start" }}>
              <SoftCard title="Messages per day" sx={{ minWidth: 0 }}>
                <PanelState query={volumeQuery} what="the message volume" height={240}>
                  {(v) => <VolumeChart volume={v} campaigns={summaryQuery.data?.campaigns ?? []} />}
                </PanelState>
              </SoftCard>
              <SoftCard title="Classification mix" caption="Messages in this period, by classification" sx={{ minWidth: 0 }}>
                <PanelState query={summaryQuery} what="the classification mix" height={120}>
                  {(s) => <MixBar mix={s.mix} unclassified={s.unclassified} />}
                </PanelState>
              </SoftCard>
            </Box>

            <SoftCard title="Campaigns in this period">
              <PanelState query={summaryQuery} what="the campaigns" height={160}>
                {(s) => <CampaignTable campaigns={s.campaigns} onSelectCases={showInMap} />}
              </PanelState>
            </SoftCard>
          </Stack>
        )}
      </Container>
    </Box>
  );
}
