// A connect is named by an attempt ID that the window gives it, so that
// CancelConnect cancels that connect alone and not one the user started
// after it. The random part keeps the IDs apart across window reloads.
const attemptPrefix = Math.random().toString(36).slice(2);
let attempts = 0;

// newConnectAttemptId returns an attempt ID for a new ConnectToServer call.
export function newConnectAttemptId(): string {
  attempts++;
  return `${attemptPrefix}-${attempts}`;
}
