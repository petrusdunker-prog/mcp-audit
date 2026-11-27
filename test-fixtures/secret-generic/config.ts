// Fixture: a credential-sounding name assigned a literal string that isn't
// a known format and isn't an obvious placeholder either — this should
// trip the generic (noisier, MEDIUM-severity) heuristic, not the
// known-format one.
export const config = {
  apiKey: "a1b2c3d4e5f6g7h8i9j0",
  placeholderKey: "YOUR_API_KEY_HERE",
};
