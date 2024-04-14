package springSecurity.springSecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import springSecurity.springSecurity.token.TokenRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        //Extracting token
        jwt = authHeader.substring(7);

        //Extract userEmail from JWT token
        userEmail = jwtService.extractUsername(jwt);

        //Check id user is not authenticated and check user details from database
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            //Finding token by generated token
            var isTokenValid = tokenRepository.findByToken(jwt)
                    //mapping result to boolean for checking if token is valid( not expired and not revoked)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    //if token is not valid return false
                    .orElse(false);

            //Check if user is valid or not
            if (jwtService.isTokenValid(jwt,userDetails) && isTokenValid){

                //if user is valid
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //Update authentication token
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            //Passing hand to next filter to be executed
            filterChain.doFilter(request, response);
        }
    }
}
