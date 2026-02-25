package com.vellaveto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Describes a tool call to be evaluated by the policy engine.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Action {

    static final int MAX_TOOL_LENGTH = 256;
    static final int MAX_FUNCTION_LENGTH = 256;
    static final int MAX_TARGET_ENTRIES = 100;

    @JsonProperty("tool")
    private final String tool;

    @JsonProperty("function")
    private final String function;

    @JsonProperty("parameters")
    private final Map<String, Object> parameters;

    @JsonProperty("target_paths")
    private final List<String> targetPaths;

    @JsonProperty("target_domains")
    private final List<String> targetDomains;

    @JsonProperty("resolved_ips")
    private final List<String> resolvedIps;

    private Action(Builder builder) {
        this.tool = builder.tool;
        this.function = builder.function;
        this.parameters = builder.parameters;
        this.targetPaths = builder.targetPaths;
        this.targetDomains = builder.targetDomains;
        this.resolvedIps = builder.resolvedIps;
    }

    public String getTool() { return tool; }
    public String getFunction() { return function; }
    public Map<String, Object> getParameters() { return parameters; }
    public List<String> getTargetPaths() { return targetPaths; }
    public List<String> getTargetDomains() { return targetDomains; }
    public List<String> getResolvedIps() { return resolvedIps; }

    /**
     * Validates that the Action fields are within safe bounds.
     * SECURITY: Client-side input validation prevents sending obviously invalid payloads.
     *
     * @throws VellavetoException if validation fails
     */
    public void validate() throws VellavetoException {
        if (tool == null || tool.isEmpty()) {
            throw new VellavetoException("action.tool must not be empty");
        }
        if (tool.length() > MAX_TOOL_LENGTH) {
            throw new VellavetoException("action.tool exceeds max length " + MAX_TOOL_LENGTH);
        }
        ValidationUtils.rejectControlAndFormatChars(tool, "action.tool");
        if (function != null) {
            if (function.length() > MAX_FUNCTION_LENGTH) {
                throw new VellavetoException("action.function exceeds max length " + MAX_FUNCTION_LENGTH);
            }
            ValidationUtils.rejectControlAndFormatChars(function, "action.function");
        }
        if (targetPaths != null && targetPaths.size() > MAX_TARGET_ENTRIES) {
            throw new VellavetoException("action.targetPaths has " + targetPaths.size()
                    + " entries, max " + MAX_TARGET_ENTRIES);
        }
        if (targetDomains != null && targetDomains.size() > MAX_TARGET_ENTRIES) {
            throw new VellavetoException("action.targetDomains has " + targetDomains.size()
                    + " entries, max " + MAX_TARGET_ENTRIES);
        }
        if (resolvedIps != null && resolvedIps.size() > MAX_TARGET_ENTRIES) {
            throw new VellavetoException("action.resolvedIps has " + resolvedIps.size()
                    + " entries, max " + MAX_TARGET_ENTRIES);
        }
    }

    public static Builder builder(String tool) {
        return new Builder(tool);
    }

    @Override
    public String toString() {
        return "Action{tool='" + tool + "', function='" + function + "'}";
    }

    public static class Builder {
        private final String tool;
        private String function;
        private Map<String, Object> parameters;
        private List<String> targetPaths;
        private List<String> targetDomains;
        private List<String> resolvedIps;

        Builder(String tool) {
            this.tool = tool;
        }

        public Builder function(String function) {
            this.function = function;
            return this;
        }

        public Builder parameters(Map<String, Object> parameters) {
            this.parameters = parameters == null ? null : Collections.unmodifiableMap(parameters);
            return this;
        }

        public Builder targetPaths(List<String> targetPaths) {
            this.targetPaths = targetPaths == null ? null : Collections.unmodifiableList(targetPaths);
            return this;
        }

        public Builder targetDomains(List<String> targetDomains) {
            this.targetDomains = targetDomains == null ? null : Collections.unmodifiableList(targetDomains);
            return this;
        }

        public Builder resolvedIps(List<String> resolvedIps) {
            this.resolvedIps = resolvedIps == null ? null : Collections.unmodifiableList(resolvedIps);
            return this;
        }

        public Action build() {
            return new Action(this);
        }
    }
}
