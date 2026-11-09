// Material swaps palettes without reloading; re-render mermaid blocks with the matching theme.
function renderMermaid() {
  var dark = document.body.getAttribute("data-md-color-scheme") === "slate";
  mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "default" });
  mermaid.run({ querySelector: ".mermaid" });
}
if (typeof document$ !== "undefined") {
  document$.subscribe(renderMermaid);
} else {
  document.addEventListener("DOMContentLoaded", renderMermaid);
}
