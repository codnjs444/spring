 	package com.mysite.sbb;

// 스프링 프레임워크의 구성 요소를 불러오는 부분입니다.
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration  // 이 클래스를 스프링 설정 클래스로 지정합니다.
@EnableWebSecurity  // 웹 보안 기능을 활성화합니다.
@EnableMethodSecurity(prePostEnabled = true)  // 메서드 단위 보안을 활성화하고, pre/post 어노테이션을 사용할 수 있게 합니다.
public class SecurityConfig {
	@Bean  // 스프링 IoC 컨테이너에 객체를 빈으로 등록합니다.
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
				.requestMatchers(new AntPathRequestMatcher("/**")).permitAll())  // 모든 경로에 대해 접근을 허용합니다.
				.csrf((csrf) -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))  // /h2-console 경로에 대해서는 CSRF 검증을 무시합니다.
				.headers((headers) -> headers.addHeaderWriter(
						new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))  // 프레임을 같은 출처에서만 허용하도록 설정합니다.
				.formLogin((formLogin) -> formLogin.loginPage("/user/login")  // 로그인 페이지 경로를 지정합니다.
						.defaultSuccessUrl("/"))  // 로그인 성공 시 리디렉션될 기본 경로입니다.
				.logout((logout) -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/user/logout"))  // 로그아웃 경로를 지정합니다.
						.logoutSuccessUrl("/").invalidateHttpSession(true));  // 로그아웃 성공 시 세션을 무효화하고, 기본 경로로 리다이렉트합니다.
		return http.build();
	}

	@Bean  // 스프링 IoC 컨테이너에 객체를 빈으로 등록합니다.
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();  // 비밀번호 암호화에 사용할 인코더로 BCryptPasswordEncoder를 사용합니다.
	}

	@Bean  // 스프링 IoC 컨테이너에 객체를 빈으로 등록합니다.
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();  // AuthenticationConfiguration을 통해 AuthenticationManager를 구성하고 반환합니다.
	}
}
