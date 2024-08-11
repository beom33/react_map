package com.joyfarm.farmstival.member.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {

    private final TokenProvider provider;
     // JWT 토큰을 생성하거나 검증하는 기능을 제공 
    /**
     * 요청 헤더 Authorization : Bearer JWT 토큰 값
     *
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
      //  doFilter 메서드는 필터의 핵심 로직을 처리함. 클라이언트에서 요청이 들어올 때마다 이 메서드가 호출된다.
        String token = getToken(request); //getToken 메서드를 사용해 HTTP 요청에서 JWT 토큰을 추출.
        if(StringUtils.hasText(token)) {
            //토큰이 존재하고 내용이 있다면, 그 토큰을 사용해 사용자를 인증한다.
            Authentication authentication = provider.getAuthentication(token);
            //TokenProvider를 통해 토큰에서 인증 정보를 추출.
            SecurityContextHolder.getContext().setAuthentication(authentication); // -> 이것을 넣으면 로그인 유지가 된다.
        }
        chain.doFilter(request, response); //다음 필터로 요청을 전달하여 계속 처리될 수 있도록 한다.
    }

    /**
     * 요청 헤더에서 JWT 토큰 추출
     * Authorization : Bearer JWT 토큰 값
     * Bearer -> 토큰 인증방식
     *
     * @param request
     * @return
     */

    private String getToken(ServletRequest request)  {
        //HTTP 요청 헤더에서 JWT 토큰을 추출하는 역할을 한다.
        HttpServletRequest req = (HttpServletRequest) request;
        //ServletRequest를 HttpServletRequest로 변환. 이렇게 해야 HTTP 요청에 접근가능.
        String bearerToken = req.getHeader("Authorization");
        //요청 헤더에서 Authorization 헤더 값을 가져온다. 이 헤더에는 JWT 토큰이 포함됨.
        if(StringUtils.hasText(bearerToken)
                && bearerToken.toUpperCase().startsWith("BEARER ")) {
              //헤더 값이 존재하고, "Bearer "로 시작하는지 확인. "Bearer"는 토큰 인증 방식의 일종.
            return bearerToken.substring(7).trim();
            //Bearer " 이후의 실제 토큰 값을 추출해 반환. 여기서 7은 "Bearer " 문자열의 길이
        }
        return null; //만약 토큰이 없거나 올바르지 않으면 null을 반환.
    }
}
