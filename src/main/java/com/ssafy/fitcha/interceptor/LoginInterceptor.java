package com.ssafy.fitcha.interceptor;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component  //등록해줘야 함.
public class LoginInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        HttpSession session = request.getSession(false); 
       /* request.getSession(false)
				→ **"이미 존재하는 세션이 있으면 가져오고, 없으면 null을 반환"**합니다.

				반대로 request.getSession(true) 또는 그냥 request.getSession()은
				→ "세션이 없으면 새로 만들어서 반환" 합니다.
				*/
				
        if (session != null && session.getAttribute("loginUser") != null) {
            return true; // 통과
        }

        response.sendRedirect(request.getContextPath()  + "/user/login"); // 로그인 페이지로 이동하라고 저장.
        return false; // 컨트롤러로 가지 않음
    }

    @Override
    public void postHandle(HttpServletRequest request,
                           HttpServletResponse response,
                           Object handler,
                           ModelAndView modelAndView) throws Exception {
        // 컨트롤러가 실행되고 나서 뷰가 렌더링되기 전
    }

    @Override
    public void afterCompletion(HttpServletRequest request,
                                HttpServletResponse response,
                                Object handler,
                                Exception ex) throws Exception {
        // 요청 처리 완료 후, 예외 발생 여부 관계 없이 실행됨 (리소스 정리 등에 사용)
    }
}