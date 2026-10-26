module.exports = {
  extends: ["@commitlint/config-conventional"],
  // Dependabot writes its own message bodies (long release-note lines) and
  // signs them off; they are not hand-written commits.
  ignores: [(message) => message.includes("Signed-off-by: dependabot[bot]")],
};
