package law.ilovelaw.payload.request;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Getter
@Setter
public class UpdateRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String name;
}
