import "@mui/material/styles";
import "@mui/material/Typography";
import type * as React from "react";

// MUI "adding variants" augmentation: the one page-title size used by every page.
declare module "@mui/material/styles" {
  interface TypographyVariants {
    pageTitle: React.CSSProperties;
  }
  interface TypographyVariantsOptions {
    pageTitle?: React.CSSProperties;
  }
}

declare module "@mui/material/Typography" {
  interface TypographyPropsVariantOverrides {
    pageTitle: true;
  }
}
