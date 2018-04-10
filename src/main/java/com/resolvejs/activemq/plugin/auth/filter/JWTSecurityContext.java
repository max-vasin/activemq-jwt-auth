package com.resolvejs.activemq.plugin.auth.filter;

import org.apache.activemq.security.SecurityContext;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

public class JWTSecurityContext extends SecurityContext {
    private Set<Principal> principals;
    private Set<String> allowedDestinations = new HashSet<>();

    JWTSecurityContext(
            String userName,
            Set<Principal> principals,
            Set<String> allowedTopics) {
        super(userName);
        this.principals = principals;
        for (String topic : allowedTopics) {
            topic = topic.trim();
            if (!topic.isEmpty())
                this.allowedDestinations.add("topic://" + topic.trim());
        }
    }

    @Override
    public Set<Principal> getPrincipals() {
        return this.principals;
    }

    public boolean verifyDestination(String fullQualifiedDestination) {
        return this.allowedDestinations.contains(fullQualifiedDestination);
    }
}
