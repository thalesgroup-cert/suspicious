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
  const src =
    avatar?.style && avatar?.seed ? renderAvatarDataUri(avatar) : "";

  if (src) {
    return <Avatar src={src} alt={initials} sx={sx} {...rest} />;
  }
  return <Avatar sx={sx} {...rest}>{initials}</Avatar>;
}
