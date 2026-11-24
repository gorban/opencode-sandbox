"""Options for the explicitly selected live workstation test."""


def pytest_addoption(parser):
    parser.addoption("--run-openai-live", action="store_true",
                     help="Offer the two attended approvals for the live OpenAI proof.")
    parser.addoption("--recover-openai-live", action="store_true",
                     help="Offer one recovery diagnostic for the unresolved workstation proposal.")
    parser.addoption("--recover-stream-live", action="store_true",
                     help="Offer the final workstation diagnostic for the revised SSE parser.")
    parser.addoption("--recover-proof-live", metavar="REVIEWED_SHA256",
                     help="Offer the one-approval recovery proof with exact reviewed source.")
    parser.addoption("--run-openai-canary-live", action="store_true",
                     help="Run the live zero-tool OpenCode + OpenAI subscription canary e2e test.")
    parser.addoption("--openai-canary-model", default=None,
                     help="Optional reviewed model slug for --run-openai-canary-live.")
    parser.addoption("--openai-canary-source-sha256", metavar="REVIEWED_SHA256", default=None,
                     help="Required exact 64-hex SHA-256 source-tree pin for --run-openai-canary-live.")
