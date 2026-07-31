import * as React from "react";
import { Box, Stack, Typography } from "@mui/material";
import { EmailOutlined } from "@mui/icons-material";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { useTheme } from "@mui/material/styles";
import { SoftCard } from "./SoftCard";

export default function ChallengedPanel(props: {
  totalCases: number;
  challengedCases: number;
}) {
  const theme = useTheme();
  const total = props.totalCases ?? 0;        // ← remplace props.totalCases
  const challenged = props.challengedCases ?? 0; // ← remplace props.challengedCases
  const normal = Math.max(0, total - challenged);
  const ratio = total > 0
    ? ((challenged / total) * 100).toFixed(1)
    : "0.0";

  const data = [
    { name: "Normal", value: normal, color: theme.palette.success.main },
    { name: "Challenged", value: challenged, color: theme.palette.warning.main },
  ].filter(d => d.value > 0);

  return (
    <SoftCard title="Challenged mails" icon={<EmailOutlined />} fillHeight>
      <Box sx={{ flex: 1, minHeight: 180 }}>
        {props.totalCases > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius={60}
                outerRadius={85}
                isAnimationActive={false}
              >
                {data.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Pie>
              <text x="50%" y="46%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ fontWeight: 950, fontSize: 22, fill: theme.palette.text.primary }}>
                  {ratio}%
                </tspan>
              </text>
              <text x="50%" y="59%" textAnchor="middle" dominantBaseline="central">
                <tspan style={{ fontSize: 11, fill: theme.palette.text.secondary }}>
                  challenged
                </tspan>
              </text>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <Stack sx={{ height: "100%", alignItems: "center", justifyContent: "center" }}>
            <Typography color="text.secondary" variant="body2">No data</Typography>
          </Stack>
        )}
      </Box>

      <Stack spacing={0.7} sx={{ mt: 1, flexShrink: 0 }}>
        {[
          { label: "Total mails", value: props.totalCases, color: theme.palette.text.secondary },
          { label: "Challenged", value: challenged, color: theme.palette.warning.main },
          { label: "Normal", value: normal, color: theme.palette.success.main },
        ].map((row) => (
          <Stack key={row.label} direction="row" sx={{ justifyContent: "space-between" }}>
            <Typography variant="body2" color="text.secondary" sx={{ fontWeight: 500 }}>
              {row.label}
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 900, color: row.color }}>
              {row.value.toLocaleString()}
            </Typography>
          </Stack>
        ))}
      </Stack>
    </SoftCard>
  );
}