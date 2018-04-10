package com.resolvejs.activemq.plugin.auth.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerFilter;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.broker.region.Subscription;
import org.apache.activemq.command.ConnectionInfo;
import org.apache.activemq.command.ConsumerInfo;
import org.apache.activemq.command.ProducerInfo;
import org.apache.activemq.security.SecurityContext;
import org.apache.activemq.jaas.GroupPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.*;

public class JWTFilter extends BrokerFilter {
    private final Logger logger = LoggerFactory.getLogger(JWTFilter.class);
    private final String jwtSelector = "JWT_CLIENT_AUTH";
    private final String secret = Base64.getEncoder().encodeToString("qwertyuiopasdfghjklzxcvbnm123456".getBytes());
    private final Set<Principal> securityGroups = new HashSet<>();
    private Broker simpleAuth;

    private static boolean isEmpty(final String s) {
        return (s == null) || s.trim().isEmpty();
    }

    private static String getClaim(Claims claims, String name) throws SecurityException {
        Object value = claims.get(name);
        String claim = (value == null) ? "" : value.toString();
        if (claim.trim().isEmpty())
            throw new SecurityException("no JWT claim '" + name + "'");
        return claim;
    }

    public JWTFilter(Broker next, Broker simpleAuth) {
        super(next);
        this.simpleAuth = simpleAuth;
        this.securityGroups.add(new GroupPrincipal("read"));
    }

    @Override
    public void addConnection(ConnectionContext context, ConnectionInfo info) throws Exception {
        String selector = info.getUserName();
        SecurityContext securityContext = context.getSecurityContext();

        if (this.jwtSelector.equals(selector)) {
            if (securityContext == null) {
                logger.info("[" + info.getClientIp() + "] addConnection: performing JWT verification");

                String token = info.getPassword();

                boolean isTokenValid = false;
                String topicClaim = null;

                try {
                    Jws<Claims> claimsJws = Jwts
                            .parser()
                            .setSigningKey(this.secret)
                            .parseClaimsJws(token);

                    if (claimsJws != null) {
                        Claims claims = claimsJws.getBody();
                        topicClaim = JWTFilter.getClaim(claims, "topic");
                        isTokenValid = true;
                    }
                } catch (Exception e) {
                    logger.warn("[" + info.getClientIp() + "] addConnection: " + e.getMessage());
                }

                if (!isTokenValid)
                    throw new SecurityException("[" + info.getClientIp() + "] addConnection: bad JWT token " + token);

                securityContext = new JWTSecurityContext(
                        "user",
                        this.securityGroups,
                        new HashSet<>(Collections.singletonList(topicClaim)));

                context.setSecurityContext(securityContext);

                logger.info("[" + info.getClientIp() + "] addConnection: JWT verification success (topic: '" + topicClaim + "')");
            }
        }

        try {
            if (securityContext != null) {
                logger.info("[" + info.getClientIp() + "] addConnection: JWT security context created. Confirming connection.");
                super.addConnection(context, info);
            } else {
                logger.info("[" + info.getClientIp() + "] addConnection: no JWT security context. Falling back to simple auth.");
                this.simpleAuth.addConnection(context, info);
            }
        } catch (Exception e) {
            logger.error("[" + info.getClientIp() + "] addConnection: failure " + e.getMessage(), e);
            context.setSecurityContext(null);
            throw e;
        }
    }

    @Override
    public Subscription addConsumer(ConnectionContext context, ConsumerInfo info) throws Exception {
        JWTSecurityContext securityContext = (JWTSecurityContext)context.getSecurityContext();

        if (securityContext != null) {
            String destination = info.getDestination().getQualifiedName();
            logger.info("addConsumer: JWT authorized consumer accessing '" + destination + "'");
            if (!securityContext.verifyDestination(destination)) {
                logger.error("access to '" + destination + "' is forbidden");
                throw new SecurityException("access to '" + destination + "' is forbidden");
            }
            return super.addConsumer(context, info);
        }

        logger.info("addConsumer: no JWT security context. Falling back to simple auth.");
        return this.simpleAuth.addConsumer(context, info);
    }

    @Override
    public void addProducer(ConnectionContext context, ProducerInfo info) throws Exception {
        // TODO: add producer/consumer rights to jwt
        super.addProducer(context, info);
    }
}
