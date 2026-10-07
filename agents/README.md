# Agents

`ADAgent`, `EndpointAgent`, `NetworkAgent`, and `WebAgent` inherit the guarded SOC pipeline from `BaseSOCAgent`, but in `multi_api` mode they do **not** share one model.

- `ADAgent` -> `SOC_AD_*`
- `EndpointAgent` -> `SOC_ENDPOINT_*`
- `NetworkAgent` -> `SOC_NETWORK_*`
- `WebAgent` -> optional `SOC_WEB_*`, otherwise Network client
- `CorrelationAgent` -> local `CORRELATION_OLLAMA_*`

Internal flow stays **OBSERVE -> RETRIEVE -> VALIDATE -> REASON -> DECIDE**. The trace remains internal. Event IDs are resolved before retrieval, retrieved playbooks are guidance rather than evidence, and the final finding is normalized/validated in code before correlation sees it.
