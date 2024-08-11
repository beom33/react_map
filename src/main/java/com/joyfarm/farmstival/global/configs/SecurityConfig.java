package com.joyfarm.farmstival.global.configs;

import com.joyfarm.farmstival.member.jwt.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(c -> c.disable()) // Cors 정책을 바꾸는 설정
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                // corsFilter를 통해 Cors 정책을 바꾼다. UsernamePasswordAuthenticationFilter.class가 하기 전에!
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                // jwtFilter를 통해 로그인 유지 처리를 한다. UsernamePasswordAuthenticationFilter.class가 하기 전에!
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 세션쪽 기술을 활용하지 않고 로그인을 유지할 것이므로 STATELESS로 무상태 처리를 한다.
                // STATELESS가 되면 세션을 사용하지 않게 된다.
                .exceptionHandling(h -> {
                    h.authenticationEntryPoint((req, res, e) -> res.sendError(HttpStatus.UNAUTHORIZED.value()));
                    // 인증되지 않은 사용자가 보호된 리소스에 접근하려 할때 401 UNAUTHORIZED 상태 코드 반환
                    h.accessDeniedHandler((req, res, e) -> res.sendError(HttpStatus.UNAUTHORIZED.value()));
                })  // 인증된 사용자가 권한이 없는 리소스에 접근하려 할때 401 UNAUTHORIZED 상태 코드 반환

                .authorizeHttpRequests(c -> {
                    c.requestMatchers(
                                    "/account",
                                    "/account/token"
                            ).permitAll() // 회원가입, 로그인(토큰)은 모든 접근 가능
                            .anyRequest().authenticated(); // 그외에는 인증 필요
                });

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // PasswordEncoder 인터페이스를 구현하는 BCryptPasswordEncoder를 반환한다.
        // BCryptPasswordEncoder는 패스워드를 안전하게 해시 처리하기 위해 사용된다.
    }
}

// 스프리링 시큐리티를 사용해 웹 애플리케이션 보안을 설정하는 내용을 담고있다.
// CSRF 보호를 비활성화하고, JWT와 CORS 필터를 추가하며, 세션을 사용하지 않는 상태로 설정
// 또한, 특정 경로는 인증 없이 접근할 수 있도록 허용하고, 나머지 경로는 인증이 필요하도록 설정
// 마지막으로 패스워드 인코딩 방식으로 BCryptPasswordEncoder를 사용해 안전하게 패스워드를 처리할 수 있게 함

//JWT 는 무엇인가? JSON Web Token의 약자로,
// 웹 애플리케이션에서 사용자의 인증과 권한을 관리하기 위해 사용되는 토큰 기반의 인증 방식