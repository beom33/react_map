package com.joyfarm.farmstival.global.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsFilterConfig { // cors 관리해주는 설정 클래스
    // CORS는 웹 애플리케이션이 다른 도메인에서 자원을 요청할 때
    // 발생할 수 있는 보안 문제를 다루는 메커니즘
    // 이 설정을 통해 어떤 도메인에서 우리 서버에 접근할 수 있는지를 제어할 수 있다


    @Value("${cors.allow.origins}") //application.properties 또는 application.yml 같은 외부 설정 파일에서
                                    // cors.allow.origins라는 설정 값을 읽어와서 allowedOrigins 변수에 저장한다.

    private String allowedOrigins; //allowedOrigins는 이 설정 값에 따라 CORS에서 허용할 도메인 정보를 담게 된다
    // Cors 관련 헤더 -> 응답 헤더에 추가한다. (서버가 자원을 줄지 말지를 알려주는 것이므로)
        @Bean
        public CorsFilter corsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            // URL 기반으로 CORS 설정을 관리하기 위한 source 객체를 생성한다
            CorsConfiguration config = new CorsConfiguration();
            config.addAllowedMethod("*"); // 모든 요청 메서드 허용
            config.addAllowedHeader("*"); // 모든 요청 헤더 허용
            if (!allowedOrigins.equals("*")) {
                config.setAllowCredentials(true);
            } // 특정 도메인만 허용하는 경우 쿠키나 인증 정보를 함께 전달할수 있도록 setAllowCredentials(true) 로 설정한다.
            config.addAllowedOrigin(allowedOrigins);
            //allowedOrigins 변수에 저장된 도메인(들)을 허용된 출처 추가
            //ex)allowedOrigins가 "https://example.com"이라면 이 도메인에서만 요청을 허용해요.
            config.addExposedHeader("*"); //서버 응답의 모든 헤더를 클라이언트에서 접근할 수 있도록 허용

            source.registerCorsConfiguration("/**", config);

            return new CorsFilter(source);
        }
}

// 이 클래스는 서버가 외부 도메인에서 들어오는 요청에 대해 어떻게 응답할지 설정하는 역할을한다.
// 어떤 도메인에서 요청을 허용할지, 어떤 HTTP 메서드와 헤더를 허용할지,
// 인증 정보를 함께 보낼지 등을 설정할수 있다.
//
