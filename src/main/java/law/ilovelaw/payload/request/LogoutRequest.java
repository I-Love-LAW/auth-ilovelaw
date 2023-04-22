package law.ilovelaw.payload.request;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
public class LogoutRequest {
    @NotBlank
    private String username;
}
