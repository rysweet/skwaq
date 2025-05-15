# Sources and Sinks Analysis Results

## Investigation ID: inv-ac7a0c64

## Summary

Error: DefaultAzureCredential failed to retrieve a token from the included credentials.
Attempted credentials:
	EnvironmentCredential: EnvironmentCredential authentication unavailable. Environment variables are not fully configured.
Visit https://aka.ms/azsdk/python/identity/environmentcredential/troubleshoot to troubleshoot this issue.
	ManagedIdentityCredential: ManagedIdentityCredential authentication unavailable, no response from the IMDS endpoint.
	SharedTokenCacheCredential: SharedTokenCacheCredential authentication unavailable. No accounts were found in the cache.
	AzureCliCredential: Failed to invoke the Azure CLI
	AzurePowerShellCredential: PowerShell is not installed
	AzureDeveloperCliCredential: {"type":"consoleMessage","timestamp":"2025-04-29T13:37:24.499339-07:00","data":{"message":"\nERROR: fetching token: AADSTS700082: The refresh token has expired due to inactivity. The token was issued on 2024-06-13T22:52:20.0335011Z and was inactive for 90.00:00:00. Trace ID: ae29f595-4fd4-48a4-9759-979eef8c0500 Correlation ID: 6e78a968-b98c-4eac-9062-52c1d64ff561 Timestamp: 2025-04-29 20:37:24Z\n"}}
{"type":"consoleMessage","timestamp":"2025-04-29T13:37:24.499596-07:00","data":{"message":"Suggestion: reauthentication required, run `azd auth login --scope https://cognitiveservices.azure.com/.default` to acquire a new token.\n"}}

To mitigate this issue, please refer to the troubleshooting guidelines here at https://aka.ms/azsdk/python/identity/defaultazurecredential/troubleshoot.

## Sources (0)

No sources identified.

## Sinks (0)

No sinks identified.

## Data Flow Paths (0)

No data flow paths identified.
