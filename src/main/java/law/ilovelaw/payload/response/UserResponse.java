package law.ilovelaw.payload.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserResponse {
    private String id;
    private String name;

    public UserResponse(String id, String name) {
        this.id = id;
        this.name = name;
    }
}
