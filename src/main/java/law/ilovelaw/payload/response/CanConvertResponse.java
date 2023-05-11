package law.ilovelaw.payload.response;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CanConvertResponse {
    private String canConvert;

    public CanConvertResponse(String canConvert) {this.canConvert = canConvert;}
}
