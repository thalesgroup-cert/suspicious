import { Avatar } from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";
import { renderAvatarDataUri, type AvatarConfig } from "@/features/profile/avatar";

export function UserAvatar({
  avatar,
  initials,
  sx,
  ...rest
}: {
  avatar?: AvatarConfig | null;
  initials: string;
  sx?: SxProps<Theme>;
} & Record<string, unknown>) {
  const effectiveSeed = avatar?.style === "initials" ? initials : avatar?.seed;
  const src =
    avatar?.style && effectiveSeed
      ? renderAvatarDataUri({ ...avatar, seed: effectiveSeed })
      : "";

  if (src) {
    return <Avatar src={src} alt={initials} sx={sx} {...rest} />;
  }
  return <Avatar sx={sx} {...rest}>{initials}</Avatar>;
}
