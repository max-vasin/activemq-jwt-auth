package com.resolvejs.activemq.plugin.auth;

import com.resolvejs.activemq.plugin.auth.filter.JWTFilter;
import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerPlugin;
import org.apache.activemq.security.AuthenticationUser;
import org.apache.activemq.security.SimpleAuthenticationPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthPlugin implements BrokerPlugin {
    private final Logger logger = LoggerFactory.getLogger(AuthPlugin.class);
    private final SimpleAuthenticationPlugin simpleAuthPlugin = new SimpleAuthenticationPlugin();

    @Override
    public Broker installPlugin(Broker broker) throws Exception {
        logger.info("installPlugin: installing JWT authentication plugin");
        return new JWTFilter(broker, simpleAuthPlugin.installPlugin(broker));
    }

    public void setUsers(Map<String, String>[] users) {
        List<AuthenticationUser> authUsers = new ArrayList<>();

        for (Map<String, String> userData : users) {
            authUsers.add(new AuthenticationUser(
                    userData.get("name"),
                    userData.get("password"),
                    userData.get("groups")));
        }

        this.simpleAuthPlugin.setUsers(authUsers);
    }
}
