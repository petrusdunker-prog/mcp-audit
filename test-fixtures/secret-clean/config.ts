// Fixture: no secrets at all — credentials are read from the environment,
// never hardcoded. Used to verify the secret check doesn't false-positive
// on a clean file.
export const config = {
  apiKey: process.env.API_KEY,
  token: process.env.AUTH_TOKEN,
};
