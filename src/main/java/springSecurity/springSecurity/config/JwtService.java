package springSecurity.springSecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.websocket.Decoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "xeHxfoP/3On0os2gnm1Ft2z3IMY4wP6J3/u64rLQoiUrsAromn+TyYwhuwJsgyG7qqesIzIbdaNCgh7qyc1s/XMWsxMRs8SXgyL5OkY3u8Abz+gYSKxno8W+XYFyovAD+T6oF4OLDRBfTFt8ZCEcxM+icXDYTPYman+6zu+y+rLeTSbfOLVId+NDstolRmuBU9ltExrb6HcFEPOED/UhlZdl6zf2eNmDINWDOLcID9QdK0u3BmWfv5QsI/Sz5SRB6BLckbevtkZTo8S4TNEW4layBzxx04/6JGgHYcmvLENz/2oswY7NUmNJTGDIJFSBKR9u7ZTClq+6Xy9yoPvYZ5gwZZ8sw/5J/5DxTk517Vg=\n";

    //Extracting username from claim
    public String extractUsername(String token) {

        return extractClaims(token, Claims::getSubject);
    }

    //Extracting single claim
    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    //Generate token from userDetails
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    //Generate token with extraClaims
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 *60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //Token validity check
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
