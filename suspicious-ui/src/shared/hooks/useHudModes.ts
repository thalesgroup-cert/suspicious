import * as React from "react";

const KEY_PIXEL = "ui.hud.pixel";
const KEY_ALERT = "ui.hud.alert";

function readBool(key: string, fallback = false) {
  try {
    const raw = localStorage.getItem(key);
    if (raw === "1") return true;
    if (raw === "0") return false;
  } catch {}
  return fallback;
}

function writeBool(key: string, value: boolean) {
  try {
    localStorage.setItem(key, value ? "1" : "0");
  } catch {}
}

export function useHudModes() {
  const [pixel, setPixel] = React.useState<boolean>(() => readBool(KEY_PIXEL, false));
  const [alert, setAlert] = React.useState<boolean>(() => readBool(KEY_ALERT, false));

  React.useEffect(() => {
    document.body.dataset.pixel = pixel ? "on" : "off";
    writeBool(KEY_PIXEL, pixel);
  }, [pixel]);

  React.useEffect(() => {
    document.body.dataset.alert = alert ? "on" : "off";
    writeBool(KEY_ALERT, alert);
  }, [alert]);

  return { pixel, setPixel, alert, setAlert };
}
