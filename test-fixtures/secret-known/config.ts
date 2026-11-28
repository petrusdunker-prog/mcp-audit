// Fixture: known-format credential shapes that should ALL still be flagged
// CRITICAL. None of these are real credentials — low-entropy, obviously
// synthetic values (repeated digits/letters) shaped to match each pattern
// structurally, while avoiding a placeholder word (example/fake/dummy/
// your/... — see secret-known-placeholder/ for that case).
//
// The Slack-token case isn't tested here as a committed fixture: GitHub's
// own push protection checks the same structural shape our tightened regex
// requires (digit-sequence-digit-sequence-random), so any value that
// satisfies our test also satisfies theirs and gets blocked on push — fair
// catch on their part, since the whole point of tightening that regex was
// to require a real-looking structure. It's tested instead in
// test/secret-stability.test.mjs, built at runtime and written to an
// ephemeral temp file never committed to git, the same way that file
// already tests other id-stability properties.
export const AWS_ACCESS_KEY_ID = "AKIA2E6K5Q7Z8X9P0R1S";
export const GITHUB_TOKEN = "ghp_00000000000000000000000000000000000000";
export const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----`;
