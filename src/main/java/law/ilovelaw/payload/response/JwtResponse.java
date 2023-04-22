package law.ilovelaw.payload.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class JwtResponse {
    private String access;
    private String refresh;
    private String username;
    private List<String> roles;

    public JwtResponse(String accessToken, String refreshToken,
                       String username, List<String> roles) {
        this.access = accessToken;
        this.refresh = refreshToken;
        this.username = username;
        this.roles = roles;
    }
}
