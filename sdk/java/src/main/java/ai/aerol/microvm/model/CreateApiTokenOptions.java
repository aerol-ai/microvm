package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The body of {@code client.tokens().create()}. All four fields are required. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateApiTokenOptions {
    private String name;
    private String role;
    private String team;
    private String expiresIn;

    public String getName() {
        return name;
    }

    /** 1 to 64 of {@code A-Z a-z 0-9 . _ -}, unique among the team's tokens. */
    public CreateApiTokenOptions setName(String name) {
        this.name = name;
        return this;
    }

    public String getRole() {
        return role;
    }

    /** {@code viewer}, {@code runner}, {@code auditor} or {@code admin}. */
    public CreateApiTokenOptions setRole(String role) {
        this.role = role;
        return this;
    }

    public String getTeam() {
        return team;
    }

    /** A team name, or {@code "*"} for every team. {@code auditor} and {@code admin} require {@code "*"}. */
    public CreateApiTokenOptions setTeam(String team) {
        this.team = team;
        return this;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    /** The lifetime: {@code "90d"}, {@code "720h"} or any Go duration. */
    public CreateApiTokenOptions setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }
}
