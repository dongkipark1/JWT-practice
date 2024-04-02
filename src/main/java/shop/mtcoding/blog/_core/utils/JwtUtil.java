package shop.mtcoding.blog._core.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import shop.mtcoding.blog.user.SessionUser;
import shop.mtcoding.blog.user.User;

import java.util.Date;

public class JwtUtil {

    //토큰 생성
    public static String create(User user){

        String jwt = JWT.create()
                .withSubject("blog")
                .withExpiresAt(new Date(System.currentTimeMillis()+ 1000*60*60)) // 1시간
                .withClaim("id", user.getId())
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512("metacoding")); // metacoding이라 적은 환경 변수의 os를 가져와야 한다

        return jwt;
    }

    //토큰 검증
    public static SessionUser verify(String jwt){
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512("metacoding"))
                .build().verify(jwt);
        int id = decodedJWT.getClaim("id").asInt();
        String username = decodedJWT.getClaim("username").asString();

        return SessionUser.builder()
                .id(id)
                .username(username)
                .build();
    }
}
