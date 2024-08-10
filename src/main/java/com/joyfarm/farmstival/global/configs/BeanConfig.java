package com.joyfarm.farmstival.global.configs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class BeanConfig { // 자주 쓰는 빈들을 수동 등록

    @Bean
    public ObjectMapper objectMapper(){
        // json 데이터를 객체로 변환하거나 그 반대로 변한할때 사용
        ObjectMapper om = new ObjectMapper();
        om.registerModule(new JavaTimeModule());
        //자바의 날짜와 시간 관련 객체들을 JSON으로 변환할 때 필요해요.
        return om;
    }

    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}   // RestTemplate 은 REST API 를 호출할 때 자주 사용하는 도구

//결론
// ObjectMapper와 RestTemplate을 스프링에서
// 관리하는 빈으로 등록하고, 필요할 때마다
// 이 빈들을 쉽게 사용할수 있게 설정하는 역할을 한다.
