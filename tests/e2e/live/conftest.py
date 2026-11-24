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
