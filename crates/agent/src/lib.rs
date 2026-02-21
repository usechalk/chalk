//! Chalk Agent — AI-powered sync diagnostics and configuration assistance.
//!
//! This crate defines the trait boundary for the agent system. The actual LLM
//! integration will be added when remix-agent-runtime is integrated in a future phase.

/// Trait for agent services that can diagnose sync issues and suggest configurations.
pub trait AgentService: Send + Sync {
    /// Analyze a sync failure and provide diagnostic information.
    fn diagnose_sync_failure(&self, error: &str, provider: &str) -> AgentResponse;

    /// Suggest configuration for a given SIS provider.
    fn suggest_config(&self, provider: &str) -> AgentResponse;
}

/// Response from the agent service.
#[derive(Debug, Clone)]
pub struct AgentResponse {
    /// Human-readable message describing the diagnosis or suggestion.
    pub message: String,
    /// Optional suggested action the user could take.
    pub suggested_action: Option<String>,
}

/// Returns whether the agent feature is enabled.
///
/// Currently always returns false. Will return true once an LLM API key
/// is configured and the agent runtime is integrated.
pub fn is_enabled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAgent;

    impl AgentService for MockAgent {
        fn diagnose_sync_failure(&self, error: &str, provider: &str) -> AgentResponse {
            AgentResponse {
                message: format!("Diagnosed error '{error}' for provider '{provider}'"),
                suggested_action: Some("Check credentials".to_string()),
            }
        }

        fn suggest_config(&self, provider: &str) -> AgentResponse {
            AgentResponse {
                message: format!("Config suggestion for {provider}"),
                suggested_action: None,
            }
        }
    }

    #[test]
    fn agent_not_enabled() {
        assert!(!is_enabled());
    }

    #[test]
    fn mock_agent_diagnose() {
        let agent = MockAgent;
        let response = agent.diagnose_sync_failure("timeout", "powerschool");
        assert!(response.message.contains("timeout"));
        assert!(response.message.contains("powerschool"));
        assert!(response.suggested_action.is_some());
    }

    #[test]
    fn mock_agent_suggest_config() {
        let agent = MockAgent;
        let response = agent.suggest_config("infinite_campus");
        assert!(response.message.contains("infinite_campus"));
        assert!(response.suggested_action.is_none());
    }

    #[test]
    fn agent_response_clone() {
        let response = AgentResponse {
            message: "test".to_string(),
            suggested_action: Some("action".to_string()),
        };
        let cloned = response.clone();
        assert_eq!(cloned.message, "test");
        assert_eq!(cloned.suggested_action.as_deref(), Some("action"));
    }
}
