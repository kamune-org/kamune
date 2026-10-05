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

// ConnectOutcome is how a ConnectToServer call ended: its session ID, or
// its error code and, for a failure other than a cancel, the error
// message.
export interface ConnectOutcome {
  sessionId: string;
  errorCode: string;
  message: string;
}

// connectOutcome waits for call, a ConnectToServer call, and returns how
// it ended. A call that failed with an error code rejects, because Wails
// drops the result of a call that returns an error; the code then comes
// as errorCode in the rejection's cause (connectError in network.go).
// Any other rejection is thrown on.
export async function connectOutcome(
  call: PromiseLike<{ sessionId: string; errorCode: string }>
): Promise<ConnectOutcome> {
  try {
    const result = await call;
    return { sessionId: result.sessionId, errorCode: result.errorCode, message: '' };
  } catch (e: any) {
    const code = e?.cause?.errorCode;
    if (typeof code !== 'string' || !code) throw e;
    return { sessionId: '', errorCode: code, message: e?.message || String(e) };
  }
}
