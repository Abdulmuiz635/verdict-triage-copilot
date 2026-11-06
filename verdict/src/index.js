// Verdict - Forge handler entry points. The manifest references these as
// index.onIssueCreated (trigger) and index.getVerdictContext (Rovo action); the
// real logic lives in ./triggers, ./actions, ./lib and ./resolvers.

export { onIssueCreated } from './triggers/onIssueCreated.js';
export { getVerdictContext } from './actions/getVerdictContext.js';
