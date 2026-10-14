import { FormControl, InputLabel, MenuItem, Select } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import type { ScopeOption } from "@/features/dashboard/api";
import { fieldLabelSx, scopeLabel } from "@/features/dashboard/format";

export default function ScopePicker(props: {
  options: ScopeOption[];
  value: string;
  onChange: (key: string) => void;
}) {
  const theme = useTheme();
  return (
    <FormControl size="small" sx={{ minWidth: 200 }}>
      <InputLabel id="dashboard-scope-label" sx={fieldLabelSx(theme.palette)}>Scope</InputLabel>
      <Select
        labelId="dashboard-scope-label"
        label="Scope"
        value={props.value}
        onChange={(e) => props.onChange(String(e.target.value))}
      >
        {props.options.map((o) => (
          <MenuItem key={o.key} value={o.key}>
            {scopeLabel(o.label, o.key)}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}
